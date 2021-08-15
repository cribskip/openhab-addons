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

/**
 * The {@link XMCameraConfiguration} class contains fields mapping thing configuration parameters.
 *
 * @author Sascha Kloß - Initial contribution
 */
public class XMCameraConfiguration {

    public static final String IP = "ip";
    public static final String USER = "user";
    public static final String PASSWORD = "password";

    public String ip;
    public String user;
    public String password;

    public String BuildDate;
    public String SN;
    public String MAC;
    public String TYPE;
    public int KEEPALIVE;
}
