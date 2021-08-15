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

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.openhab.core.thing.ThingTypeUID;

/**
 * The {@link XMCameraBindingConstants} class defines common constants, which are
 * used across the whole binding.
 *
 * @author Sascha Kloß - Initial contribution
 */
@NonNullByDefault
public class XMCameraBindingConstants {

    private static final String BINDING_ID = "xmcamera";

    // List of all Thing Type UIDs
    public static final ThingTypeUID THING_TYPE_XMCAMERA = new ThingTypeUID(BINDING_ID, "xmipcamera");
    public static final ThingTypeUID THING_TYPE_XMNVR = new ThingTypeUID(BINDING_ID, "xmipnvr");

    // List of all Channel ids
    public static final String CHANNEL_SNAPSHOT = "snapshot";
    public static final String CHANNEL_PLAYSOUND = "playsound";
    public static final String CHANNEL_PLAY = "play";

    public static final int XM_CODE_OK = 100;
    public static final int XM_CODE_UnknownError = 101;
    public static final int XM_CODE_UnsupportedVersion = 102;
    public static final int XM_CODE_RequestNotPermitted = 103;
    public static final int XM_CODE_UserAlreadyLoggedIn = 104;
    public static final int XM_CODE_UserIsNotLoggedIn = 105;
    public static final int XM_CODE_CredentialsIncorrect = 106;
    public static final int XM_CODE_InsufficientPermissions = 107;
    public static final int XM_CODE_PasswordIncorrect = 203;

    /*
     * public static final int XM_CODE_Start of upgrade"=511;
     * public static final int XM_CODE_Upgrade was not started"=512;
     * public static final int XM_CODE_Upgrade data errors"=513;
     * public static final int XM_CODE_Upgrade error"=514;
     */

    // XM QCODES
    public static final int XM_QCODE_Login = 1000;
    public static final int XM_QCODE_AuthorityList = 1470;
    public static final int XM_QCODE_Users = 1472;
    public static final int XM_QCODE_Groups = 1474;
    public static final int XM_QCODE_AddGroup = 1476;
    public static final int XM_QCODE_ModifyGroup = 1478;
    public static final int XM_QCODE_DelGroup = 1480;
    public static final int XM_QCODE_AddUser = 1482;
    public static final int XM_QCODE_ModifyUser = 1484;
    public static final int XM_QCODE_DelUser = 1486;
    public static final int XM_QCODE_ModifyPassword = 1488;
    public static final int XM_QCODE_AlarmInfo = 1504;
    public static final int XM_QCODE_AlarmSet = 1500;
    public static final int XM_QCODE_ChannelTitle = 1046;
    public static final int XM_QCODE_ChannelTitle_GET = 1048;

    public static final int XM_QCODE_EncodeCapability = 1360;
    public static final int XM_QCODE_General = 1042;
    public static final int XM_QCODE_KeepAlive = 1006;
    public static final int XM_QCODE_OPMachine = 1450;
    public static final int XM_QCODE_OPMailTest = 1636;
    public static final int XM_QCODE_OPMonitor = 1413;
    public static final int XM_QCODE_OPNetKeyboard = 1550;
    public static final int XM_QCODE_OPPTZControl = 1400;
    public static final int XM_QCODE_OPSNAP = 1560;
    public static final int XM_QCODE_OPSendFile = 0x5F2;
    public static final int XM_QCODE_OPSystemUpgrade = 0x5F5;
    public static final int XM_QCODE_OPTalk = 1434;

    public static final int XM_QCODE_KEEPALIVE_REQ = 1006; // 1005;
    public static final int XM_QCODE_KEEPALIVE_RSP = 1007; // 1006;
    public static final int XM_QCODE_TIMEQUERY_REQ = 1452;
    public static final int XM_QCODE_TIMEQUERY_RSP = 1453;
    public static final int XM_QCODE_TALK_REQ = 1430;
    public static final int XM_QCODE_TALK_RSP = 1431;
    public static final int XM_QCODE_TALK_CU_PU_DATA = 1432;
    public static final int XM_QCODE_TALK_PU_CU_DATA = 1433;
    public static final int XM_QCODE_TALK_CLAIM = 1434;
    public static final int XM_QCODE_TALK_CLAIM_RSP = 1435;

    public static final int XM_QCODE_OPTimeQuery = 1452;
    public static final int XM_QCODE_OPTimeSetting = 1450;
    public static final int XM_QCODE_NetWorkNetCommon = 1042;
    public static final int XM_QCODE_OPNetAlarm = 1506;
    public static final int XM_QCODE_SystemFunction = 1360;
    public static final int XM_QCODE_SystemInfo = 1020;

}
