/**
 * Copyright (c) 2010-2021 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.binding.xmcamera.internal;

import static org.openhab.binding.xmcamera.internal.XMCameraBindingConstants.*;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.core.thing.ChannelUID;
import org.openhab.core.thing.Thing;
import org.openhab.core.thing.ThingStatus;
import org.openhab.core.thing.ThingStatusDetail;
import org.openhab.core.thing.binding.BaseThingHandler;
import org.openhab.core.types.Command;
import org.openhab.core.types.RefreshType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * The {@link XMCameraHandler} is responsible for handling commands, which are
 * sent to one of the channels.
 *
 * @author Sascha Kloß - Initial contribution
 */
@NonNullByDefault
public class XMCameraHandler extends BaseThingHandler {

    private final Logger logger = LoggerFactory.getLogger(XMCameraHandler.class);

    private @Nullable XMCameraConfiguration config;

    private @Nullable Socket socket;
    private @Nullable Socket talksocket;
    private int SessionID;
    private int Sequence;
    private @Nullable ScheduledFuture<?> heartbeat;

    static final Pattern pattern_initSession = Pattern.compile(
            "\\{ \"AliveInterval\" : ([0-9]+), \"ChannelNum\" : ([0-9]+), \"DeviceType \" : \"([a-zA-Z]+)\", \"ExtraChannel\" : ([0-9]+), \"Ret\" : ([0-9]+), \"SessionID\" : \"0x([0-9A-F]+)\" \\}");

    public XMCameraHandler(Thing thing) {
        super(thing);
    }

    // Taken from https://stackoverflow.com/questions/46280158/get-alarms-events-from-ip-camera-hi3518
    private static String sofia_hash(String msg) throws NoSuchAlgorithmException {
        String hash = "";
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(msg.getBytes(StandardCharsets.UTF_8));
        byte[] msg_md5 = md.digest();
        for (int i = 0; i < 8; i++) {
            int n = ((msg_md5[2 * i] & 0xFF) + (msg_md5[2 * i + 1] & 0xFF)) % 0x3e;
            if (n > 9) {
                if (n > 35) {
                    n += 61;
                } else {
                    n += 55;
                }
            } else {
                n += 0x30;
            }
            hash += (char) n;
        }
        return hash;
    }

    private String _generic_command(int msgid, byte[] params, @Nullable Socket s) throws IOException {
        Map response_head = this._generic_command_head(msgid, params, s);
        String out = this._get_response_data(response_head, s);

        return out;
    }

    private Map _generic_command_head(int msgid, byte[] params, @Nullable Socket s) throws IOException {
        // if msgid != xmconst.LOGIN_REQ2 and type(params) != bytes:
        // pkt['SessionID'] = self._build_packet_sid()

        byte[] cmd_data = buildPacket(msgid, params);
        s.getOutputStream().write(cmd_data);

        return this._get_response_head(s);
    }

    private void cmd_channel_title() throws IOException {
        String initRequestStr = String.format("{ \"Name\" : \"ChannelTitle\" }\n", "");

        // System.out.println(this._generic_command(XM_QCODE_ChannelTitle_GET, initRequestStr, this.socket));

        return;
    }

    private Map _get_response_head(@Nullable Socket s) throws IOException {
        Map map = new HashMap();
        try {
            byte head_flag, version, channel, endflag;
            int sid, seq, size, msgid;

            {
                byte[] data = new byte[4];
                data = s.getInputStream().readNBytes(4);
                ByteBuffer bb = ByteBuffer.wrap(data);
                bb.order(ByteOrder.LITTLE_ENDIAN);

                head_flag = bb.get();
                version = bb.get();
            }

            {
                byte[] data = new byte[8];
                data = s.getInputStream().readNBytes(8);
                ByteBuffer bb = ByteBuffer.wrap(data);
                bb.order(ByteOrder.LITTLE_ENDIAN);
                sid = bb.getInt();
                seq = bb.getInt();

            }

            {
                byte[] data = new byte[8];
                data = s.getInputStream().readNBytes(8);
                ByteBuffer bb = ByteBuffer.wrap(data);
                bb.order(ByteOrder.LITTLE_ENDIAN);

                channel = bb.get();
                endflag = bb.get();
                msgid = bb.getShort();
                size = bb.getInt();
            }

            this.Sequence = seq;
            this.SessionID = sid;

            map.put("Version", version);
            map.put("SessionID", sid);
            map.put("Sequence", seq);
            map.put("MessageID", msgid);
            map.put("Content_Length", size);

            return map;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return map;
    }

    private String _get_response_data(Map reply_head, @Nullable Socket s) throws IOException {
        int length = (int) reply_head.get("Content_Length");
        String out = "";

        InputStream in = s.getInputStream();

        for (int i = 0; i < length; i++) {
            byte data = (byte) in.read();
            out += (char) data;
        }

        logger.trace(out);

        return out;
    }

    private byte[] buildPacket(int msgid, byte[] data) {
        byte[] buffer = new byte[4 + 4 + 4 + 4 + 4 + data.length + 4];

        try {
            ByteBuffer bb = java.nio.ByteBuffer.wrap(buffer);
            bb.order(ByteOrder.LITTLE_ENDIAN);

            // 4 Bytes Intro
            bb.put((byte) 0xFF);
            bb.put((byte) 0x00);
            bb.put((byte) 0x00);
            bb.put((byte) 0x00);

            // I / Session ID / 4B
            bb.putInt(this.SessionID);

            // I / Packet_Count / 4B
            bb.putInt(0);

            // H / msg / 2x2B
            bb.putShort((short) 0);
            bb.putShort((short) msgid);

            // I / length / 4B
            bb.putInt(data.length + 2);

            // variable length
            bb.put(data);

            // Padding / 2B
            bb.put((byte) 0x0A);
            bb.put((byte) 0x00);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return buffer;
    }

    private boolean login(Socket s, String user, String password) {
        try {
            String initRequestStr = String.format(
                    "{ \"EncryptType\" : \"MD5\", \"LoginType\" : \"DVRIP-Web\", \"PassWord\" : \"%s\", \"UserName\" : \"%s\" }\n",
                    sofia_hash(password), user);

            String initResponse = this._generic_command(XM_QCODE_Login, initRequestStr.getBytes(), s);

            JsonObject Response = new JsonParser().parse(initResponse.trim()).getAsJsonObject();
            int rc = Response.get("Ret").getAsInt();

            logger.info(initResponse);

            if (rc == 100) {

                Map<String, String> properties = editProperties();
                properties.put("TYPE", Response.get("DeviceType ").getAsString());
                properties.put("KEEPALIVE", Response.get("DeviceAliveInterval ").getAsString());
                updateProperties(properties);

                return true;
            }
        } catch (Exception e) {
            System.out.println(e.getLocalizedMessage());
        }

        return false;
    }

    private void sendHeartbeat() {
        try {
            logger.debug("Sending heartbeat");

            String initRequestStr = "{ \"Name\" : \"KeepAlive\" }\n";

            System.out.println(this._generic_command(XM_QCODE_KEEPALIVE_REQ, initRequestStr.getBytes(), this.socket));

            updateStatus(ThingStatus.ONLINE);
        } catch (Exception e) {
            logger.warn("Problem with mylink during heartbeat: {}", e.getMessage());
            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.COMMUNICATION_ERROR, e.getMessage());
        }
    }

    private void cancelHeartbeat() {
        logger.debug("Stopping heartbeat");
        ScheduledFuture<?> heartbeat = this.heartbeat;

        if (heartbeat != null) {
            logger.debug("Cancelling heartbeat job");
            heartbeat.cancel(true);
            this.heartbeat = null;
        } else {
            logger.debug("Heartbeat was not active");
        }
    }

    private void PlaySound() throws IOException {
        Socket s = null;

        try {
            // Open file
            // pcmdata = open(pcmfile, 'rb').read()
            Path path = Paths.get("/Users/sascha/doorbell.mp3.pcm");
            // Path path = Paths.get("/Users/sascha/test");
            byte[] raw = java.nio.file.Files.readAllBytes(path);

            // Read chunks
            // data = [pcmdata[i:i+320] for i in range(0, len(pcmdata), 320)]

            config = getConfigAs(XMCameraConfiguration.class);
            s = new Socket(config.ip, 34567);

            cmd_talk_claim(s);
            cmd_talk_start(s);

            System.out.println("Begin");
            ByteBuffer bb = java.nio.ByteBuffer.wrap(raw);
            bb.order(ByteOrder.LITTLE_ENDIAN);

            int blockSize = 320;
            int blockCount = (raw.length + blockSize - 1) / blockSize;
            byte[] range = new byte[320];

            for (int i = 1; i < blockCount; i++) {
                bb.get(range);
                System.out.println("I: " + i);
                cmd_talk_send_stream(s, range);
            }
            System.out.println("Ende");

            // cmd_talk_stop(s);

        } catch (Exception e) {
            e.printStackTrace();
        }

        s.close();
    }

    private String cmd_get_time(@Nullable Socket s) throws IOException {
        String out = "{ \"Name\": \"OPTimeQuery\" }\n";

        String response = this._generic_command(XM_QCODE_TIMEQUERY_REQ, out.getBytes(), s);
        return response;
    }

    private boolean cmd_talk_claim(@Nullable Socket s) {
        try {
            logger.info("Claiming Talk");

            String out = "{ \"Name\": \"OPTalk\", \"OPTalk\": {\n\"Action\": \"Claim\", \"AudioFormat\": { \"EncodeType\": \"G711_ALAW\", \"BitRate\": 0, \"SampleBit\": 8, \"SampleRate\": 8} } }\n";

            String response = this._generic_command(XM_QCODE_TALK_CLAIM, out.getBytes(), s);
            System.out.println(response);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return false;
    }

    private boolean cmd_talk_start(@Nullable Socket s) {
        try {
            logger.info("Starting Talk");

            String out = "{ \"Name\": \"OPTalk\", \"OPTalk\": {\n\"Action\": \"Start\", \"AudioFormat\": { \"EncodeType\": \"G711_ALAW\", \"BitRate\": 128, \"SampleBit\": 8, \"SampleRate\": 8000} } }\n";

            String response = this._generic_command(XM_QCODE_TALK_REQ, out.getBytes(), s);
            // System.out.println(response);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return false;
    }

    private boolean cmd_talk_stop(@Nullable Socket s) {
        try {
            logger.info("Stopping Talk");
            String out = "{ \"Name\": \"OPTalk\", \"OPTalk\": {\n\"Action\": \"Stop\", \"AudioFormat\": { \"EncodeType\": \"G711_ALAW\", \"BitRate\": 128, \"SampleBit\": 8, \"SampleRate\": 8000} } }\n";

            String response = _generic_command(XM_QCODE_TALK_REQ, out.getBytes(), s);
            // System.out.println(response);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return false;
    }

    private void cmd_talk_send_stream(@Nullable Socket s, byte[] data) throws IOException {
        // #assert type(data) == bytes, 'Data should be a PCM bytes type'
        // # final_data = bytes.fromhex('000001fa0e024001') + data

        byte[] buffer = new byte[8 + 6 + data.length];

        ByteBuffer bb = java.nio.ByteBuffer.wrap(buffer);
        bb.order(ByteOrder.LITTLE_ENDIAN);

        bb.putShort((short) 0);
        bb.put((byte) 0x01);
        bb.put((byte) 0xFA);
        bb.put((byte) 0x0E);
        bb.put((byte) 0x02);
        bb.put((byte) 0x40);
        bb.put((byte) 0x01);

        bb.put(data);
        System.out.println("Stream");

        _generic_command_head(XM_QCODE_TALK_CU_PU_DATA, buffer, s);
    }

    @Override
    public void handleCommand(ChannelUID channelUID, Command command) {

        logger.info("handleCommand: " + channelUID.getId());
        if (CHANNEL_SNAPSHOT.equals(channelUID.getId())) {
            if (command instanceof RefreshType) {
                // TODO: handle data refresh
            }

            // TODO: handle command

            // Note: if communication with thing fails for some reason,
            // indicate that by setting the status with detail information:
            // updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.COMMUNICATION_ERROR,
            // "Could not control device at IP address x.x.x.x");
        } else if (CHANNEL_PLAYSOUND.equals(channelUID.getId())) {
            if (command instanceof RefreshType) {

            }

        } else if (CHANNEL_PLAY.equals(channelUID.getId())) {
            if (command instanceof RefreshType) {

            }
            try {
                PlaySound();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            //
            // updateState(CHANNEL_PLAY, (OnOffType) command);

            // this.socket = new Socket(config.ip, 34567);
            // loginPossible = login(this.socket, config.user, config.password);

            // Note: if communication with thing fails for some reason,
            // indicate that by setting the status with detail information:
            // updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.COMMUNICATION_ERROR,
            // "Could not control device at IP address x.x.x.x");
        }
    }

    @Override
    public void initialize() {
        // config = getConfigAs(XMCameraConfiguration.class);

        // TODO: Initialize the handler.
        // The framework requires you to return from this method quickly. Also, before leaving this method a thing
        // status from one of ONLINE, OFFLINE or UNKNOWN must be set. This might already be the real thing status in
        // case you can decide it directly.
        // In case you can not decide the thing status directly (e.g. for long running connection handshake using
        // WAN
        // access or similar) you should set status UNKNOWN here and then decide the real status asynchronously in
        // the
        // background.

        // set the thing status to UNKNOWN temporarily and let the background task decide for the real status.
        // the framework is then able to reuse the resources from the thing handler initialization.
        // we set this upfront to reliably check status updates in unit tests.
        updateStatus(ThingStatus.UNKNOWN);

        // Example for background initialization:
        scheduler.execute(() -> {
            config = getConfigAs(XMCameraConfiguration.class);
            boolean loginPossible = false;
            try {
                this.socket = new Socket(config.ip, 34567);
                loginPossible = login(this.socket, config.user, config.password);
                config = getConfigAs(XMCameraConfiguration.class);
                // this.cmd_channel_title();

                if (heartbeat == null) {
                    logger.info("Starting heartbeat job every {} secs", config.KEEPALIVE - 2);
                    heartbeat = this.scheduler.scheduleWithFixedDelay(this::sendHeartbeat, 0, 20, TimeUnit.SECONDS);
                }

            } catch (Exception e) {
                e.printStackTrace();
            }

            if (loginPossible) {
                updateStatus(ThingStatus.ONLINE);
            } else {
                updateStatus(ThingStatus.OFFLINE);
            }
        });

        // These logging types should be primarily used by bindings
        // logger.trace("Example trace message");
        // logger.debug("Example debug message");
        // logger.warn("Example warn message");

        // Note: When initialization can NOT be done set the status with more details for further
        // analysis. See also class ThingStatusDetail for all available status details.
        // Add a description to give user information to understand why thing does not work as expected. E.g.
        // updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
        // "Can not access device as username and/or password are invalid");
    }

    @Override
    public void dispose() {
        cancelHeartbeat();
        // dispose(commandExecutor);
    }

}
