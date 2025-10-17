import subprocess
import usb.core
import usb.util

CDC_CMDS = {
    "SEND_ENCAPSULATED_COMMAND": 0x00,
    "GET_ENCAPSULATED_RESPONSE": 0x01,
    "SET_COMM_FEATURE": 0x02,
    "GET_COMM_FEATURE": 0x03,
    "CLEAR_COMM_FEATURE": 0x04,
    "SET_LINE_CODING": 0x20,
    "GET_LINE_CODING": 0x21,
    "SET_CONTROL_LINE_STATE": 0x22,
    "SEND_BREAK": 0x23,   # wValue is break time
}

FTDI_CMDS = {
    "read_8bit_addr": 0x90,
    "read_16bit_addr": 0x91,
    "write_8bit_addr": 0x92,
    "write_16bit_addr": 0x93,
    "set_hight_byte": 0x82,
    "read_high_byte": 0x83
}

cmd = "Get-CimInstance -Class Win32_PnPSignedDriver | Where-Object { $_.DeviceID -like 'USB\*' } | Select-Object Description, DeviceID, Manufacturer"
res = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
lines = res.stdout.strip().split("\n")
for line in lines[2:]:
    print(line.strip())

vid = int(input("Enter Vendor ID (hex): "), 16)
pid = int(input("Enter Product ID (hex): "), 16)

dev = usb.core.find(idProduct=pid, idVendor=vid)
dev.set_configuration()
cfg = dev.get_active_configuration()
#print(cfg)
iface = cfg[(0, 0)]
print(iface)

epo = usb.util.find_descriptor(iface, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT)
epi = usb.util.find_descriptor(iface, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN)

print(epo)
print("-"*20)
print(epi)
print("-"*20)
print(dev.bLength)
print(dev.bNumConfigurations)
print(dev.bDeviceClass)


cfg_dict = {}

c = dev
cfg_dict[c.serial_number] = {
    "manufacturer": c.manufacturer,
    "product": c.product,
    "port_num": c.port_number,
    "address": c.address,
    "bus": c.bus,
    "langids": c.langids,
    "speed": c.speed
}
print("-"*20)
print(cfg_dict)