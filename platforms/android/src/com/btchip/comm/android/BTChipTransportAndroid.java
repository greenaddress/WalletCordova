/*
*******************************************************************************    
*   BTChip Bitcoin Hardware Wallet Java API
*   (c) 2014 BTChip - 1BTChip7VfTnrPra5jqci7ejnMguuHogTn
*   
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*   limitations under the License.
********************************************************************************
*/

package com.btchip.comm.android;

import java.util.HashMap;

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;

import com.btchip.BTChipException;
import com.btchip.comm.BTChipTransport;

public class BTChipTransportAndroid implements BTChipTransport {
	
	private UsbDeviceConnection connection;
	private UsbInterface dongleInterface;
	private UsbEndpoint in;
	private UsbEndpoint out;
	private int timeout;
	private byte transferBuffer[];
	
	BTChipTransportAndroid(UsbDeviceConnection connection, UsbInterface dongleInterface, UsbEndpoint in, UsbEndpoint out, int timeout) {
		this.connection = connection;
		this.dongleInterface = dongleInterface;
		this.in = in;
		this.out = out;
		this.timeout = timeout;
		transferBuffer = new byte[260];
	}

	@Override
	public byte[] exchange(byte[] command) throws BTChipException {
		int result = connection.bulkTransfer(out, command, command.length, timeout);
		if (result != command.length) {
			throw new BTChipException("Write failed");
		}
		result = connection.bulkTransfer(in, transferBuffer, transferBuffer.length, timeout);
		if (result < 0) {
			throw new BTChipException("Write failed");
		}
		int sw1 = (int)(transferBuffer[0] & 0xff);
		int sw2 = (int)(transferBuffer[1] & 0xff);
		if (sw1 != SW1_DATA_AVAILABLE) {
			byte[] response = new byte[2];
			response[0] = (byte)sw1;
			response[1] = (byte)sw2;
			return response;
		}
		byte[] response = new byte[sw2 + 2];
		System.arraycopy(transferBuffer, 2, response, 0, sw2 + 2);
		return response;
	}

	@Override
	public void close() throws BTChipException {
		connection.releaseInterface(dongleInterface);
		connection.close();
	}
	
	public static UsbDevice getDevice(UsbManager manager) {
		HashMap<String, UsbDevice> deviceList = manager.getDeviceList();
		for (UsbDevice device : deviceList.values()) {
			if ((device.getVendorId() == VID) && (device.getProductId() == PID)) {
				return device;
			}
		}
		return null;		
	}
	
	public static BTChipTransportAndroid open(UsbManager manager, UsbDevice device) {
		// Must only be called once permission is granted (see http://developer.android.com/reference/android/hardware/usb/UsbManager.html)
		// Important if enumerating, rather than being awaken by the intent notification
		UsbInterface dongleInterface = device.getInterface(0);
        UsbEndpoint in = null;
        UsbEndpoint out = null;
        for (int i=0; i<dongleInterface.getEndpointCount(); i++) {
            UsbEndpoint tmpEndpoint = dongleInterface.getEndpoint(i);
            if (tmpEndpoint.getDirection() == UsbConstants.USB_DIR_IN) {
                in = tmpEndpoint;
            }
            else {
                out = tmpEndpoint;
            }
        }
        UsbDeviceConnection connection = manager.openDevice(device);
        connection.claimInterface(dongleInterface, true);
        return new BTChipTransportAndroid(connection, dongleInterface, in, out, TIMEOUT);        
	}
	
	private static final int SW1_DATA_AVAILABLE = 0x61;
	private static final int VID = 0x2581;
	private static final int PID = 0x1b7c;
	private static final int TIMEOUT = 20000;	
}
