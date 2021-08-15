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
package org.openhab.binding.xmcamera.internal.discovery;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.binding.xmcamera.internal.XMCameraBindingConstants;
import org.openhab.binding.xmcamera.internal.XMCameraConfiguration;
import org.openhab.core.config.discovery.AbstractDiscoveryService;
import org.openhab.core.config.discovery.DiscoveryResult;
import org.openhab.core.config.discovery.DiscoveryResultBuilder;
import org.openhab.core.config.discovery.DiscoveryService;
import org.openhab.core.net.NetUtil;
import org.openhab.core.thing.ThingUID;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Discovery service for XM IP Cameras.
 *
 * @author Sascha Kloß - Initial contribution
 *
 */

/*
 * Original Code from
 * https://github.com/NeiroNx/python-dvr/blob/3741587033b45e2b067db645f74fd6b948d5498f/DeviceManager.py#L207:
 * def SearchXM(devices):
 * server = socket(AF_INET, SOCK_DGRAM)
 * server.bind(("", 34569))
 * server.settimeout(1)
 * server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
 * server.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
 * server.sendto(
 * struct.pack("BBHIIHHI", 255, 0, 0, 0, 0, 0, 1530, 0), ("255.255.255.255", 34569)
 * )
 * while True:
 * data = server.recvfrom(1024)
 * head, ver, typ, session, packet, info, msg, leng = struct.unpack(
 * "BBHIIHHI", data[0][:20]
 * )
 * if (msg == 1531) and leng > 0:
 * answer = json.loads(
 * data[0][20 : 20 + leng].replace(b"\x00", b""))
 * if answer["NetWork.NetCommon"]["MAC"] not in devices.keys():
 * devices[answer["NetWork.NetCommon"]["MAC"]] = answer[
 * "NetWork.NetCommon"
 * ]
 * devices[answer["NetWork.NetCommon"]["MAC"]][u"Brand"] = u"xm"
 * server.close()
 * return devices
 */

/*
 * Discovery Service for XM IP Camera
 *
 * @author Sascha Kloß - Initial contribution
 */
@Component(service = DiscoveryService.class)
@NonNullByDefault
public class XMCameraDiscoveryService extends AbstractDiscoveryService {
    private static final byte[] UDP_PACKET_CONTENTS = { (byte) 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xFA, 0x05, 0x00, 0x00, 0x00, 0x00 };
    private static final int REMOTE_UDP_PORT = 34569;

    private Logger logger = LoggerFactory.getLogger(XMCameraDiscoveryService.class);

    private final Runnable scanner;
    private @Nullable ScheduledFuture<?> backgroundFuture;

    public XMCameraDiscoveryService() {
        super(Collections.singleton(XMCameraBindingConstants.THING_TYPE_XMCAMERA), 600, true);
        scanner = createScanner();
    }

    @Override
    protected void startScan() {
        scheduler.execute(scanner);
    }

    @Override
    protected void startBackgroundDiscovery() {
        logger.debug("Starting background discovery");

        if (backgroundFuture != null && !backgroundFuture.isDone()) {
            backgroundFuture.cancel(true);
            backgroundFuture = null;
        }
        backgroundFuture = scheduler.scheduleWithFixedDelay(scanner, 0, 60, TimeUnit.SECONDS);
    }

    @Override
    protected void stopBackgroundDiscovery() {
        if (backgroundFuture != null && !backgroundFuture.isDone()) {
            backgroundFuture.cancel(true);
            backgroundFuture = null;
        }

        super.stopBackgroundDiscovery();
    }

    private Runnable createScanner() {
        return () -> {
            long timestampOfLastScan = getTimestampOfLastScan();

            for (InetAddress broadcastAddress : getBroadcastAddresses()) {
                logger.debug("Starting broadcast for {}", broadcastAddress.toString());

                try (DatagramSocket socket = new DatagramSocket(34569)) {
                    socket.setBroadcast(true);
                    socket.setReuseAddress(true);
                    byte[] packetContents = UDP_PACKET_CONTENTS;
                    DatagramPacket packet = new DatagramPacket(packetContents, packetContents.length, broadcastAddress,
                            REMOTE_UDP_PORT);

                    // Send before listening in case the port isn't bound until here.
                    socket.send(packet);

                    logger.debug("Discovery sent for {}", broadcastAddress);

                    // receivePacketAndDiscover will return false if no packet is received after 1 second
                    while (receivePacketAndDiscover(socket)) {
                    }
                } catch (Exception e) {
                    // Nothing to do here - the host couldn't be found, likely because it doesn't exist
                }
            }

            removeOlderResults(timestampOfLastScan);
        };
    }

    private boolean receivePacketAndDiscover(DatagramSocket socket) {
        try {
            byte[] buffer = new byte[1024];
            DatagramPacket incomingPacket = new DatagramPacket(buffer, buffer.length);
            socket.setSoTimeout(1000 /* one second */);
            socket.receive(incomingPacket);

            String host = incomingPacket.getAddress().toString().substring(1);
            logger.debug("from {}, {}", host, InetAddress.getLocalHost().toString().substring(1));

            if (host == InetAddress.getLocalHost().toString()) {
                logger.debug("Ignored {} because its localhost.", host);
            } else {
                String data = new String(incomingPacket.getData(), 0, incomingPacket.getLength(), "US-ASCII");

                if (data.indexOf("{ \"BuildDate") > 0) {
                    // Crop
                    data = data.substring(data.indexOf(":") + 1);
                    data = data.substring(0, data.indexOf("}") + 1);
                    logger.debug("Received packet: {}", data);

                    JsonObject jsonObject = new JsonParser().parse(data).getAsJsonObject();

                    // String Firmware = jsonObject.get("Version").getAsString();
                    String SN = jsonObject.get("SN").getAsString();
                    String MAC = jsonObject.get("MAC").getAsString();

                    String thingId = host.replace(".", "-");

                    ThingUID thingUID = new ThingUID(XMCameraBindingConstants.THING_TYPE_XMCAMERA, thingId);

                    DiscoveryResultBuilder resultBuilder = DiscoveryResultBuilder.create(thingUID)
                            .withProperty(XMCameraConfiguration.IP, host)
                            .withProperty(XMCameraConfiguration.USER, "admin")
                            .withProperty(XMCameraConfiguration.PASSWORD, "").withProperty("SN", SN)
                            .withProperty("MAC", MAC).withLabel("XM IP Camera(" + host + ")")
                            .withRepresentationProperty("SN");

                    DiscoveryResult result = resultBuilder.build();

                    logger.debug("Successfully discovered host {}", host);
                    thingDiscovered(result);
                }
            }

            return true;

        } catch (Exception e) {
            // logger.error(e.getMessage());
        }

        // Shouldn't get here unless we don't detect a controller.
        // Return true to continue with the next packet, which comes from another adapter
        return true;
    }

    private List<InetAddress> getBroadcastAddresses() {
        ArrayList<InetAddress> addresses = new ArrayList<>();

        for (String broadcastAddress : NetUtil.getAllBroadcastAddresses()) {
            try {
                addresses.add(InetAddress.getByName(broadcastAddress));
            } catch (UnknownHostException e) {
                logger.debug("Error broadcasting to {}", broadcastAddress, e);
            }
        }

        return addresses;
    }
}
