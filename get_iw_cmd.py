import sys


def get_2g_freq(channel, width):
    res = "freq: {} width: {} center_freq: {}"
    if channel < 1 or channel > 13:
        raise ValueError("Valid 2GHz channels: [1...13], Valid 2GHz widths: [20|40]")
    
    freq = channel * 5 + 2407
    if width == 20:
        res = [freq, width]
    elif width == 40 and channel <= 7:
        res = [freq, width, freq+10]
    elif width == 40 and channel >= 5:
        res = [freq, width, freq-10]
    else:
        raise ValueError("Valid 2GHz channels: [1...13], Valid 2GHz widths: [20|40]")
    return res

def get_5g_freq(channel, width):
    res = "freq: {} width: {} center_freq: {}"
    center_freqs_5g = {
        36: [38, 42, 50], 40: [38, 42, 50], 44: [46, 42, 50], 48: [46, 42, 50],
        52: [54, 58, 50], 56: [54, 58, 50], 60: [62, 58, 50], 64: [62, 58, 50],
        100: [102, 106, 114], 104: [102, 106, 114], 108: [110, 106, 114], 112: [110, 106, 114],
        116: [118, 122, 114], 120: [118, 122, 114], 124: [126, 122, 114], 128: [126, 122, 114],
        132: [134, 138], 136: [134, 138], 140: [142, 138], 144: [142, 138], 
        149: [151, 155, 163], 153: [151, 155, 163], 157: [159, 155, 163], 161: [159, 155, 163],
        165: [167, 171, 163], 169: [167, 171, 163], 173: [175, 171, 163], 177: [175, 171, 163]
    }
    offset_index = 0
    freq = channel * 5 + 5000

    if width == 20:
        if channel % 4 != 0 and (channel >= 149 and channel % 4 != 1):
            raise ValueError("Invalid 5GHz channel: {}".format(channel))
        else:
            return [freq, width]
    elif width == 40:
        width = 40
        offset_index = 0
    elif width == 80:
        offset_index = 1
    elif width == 160:
        offset_index = 2
    else:
        raise ValueError("Supported 5GHz widths: [20|40|80|160]")

    try:
        offset = center_freqs_5g[channel][offset_index]
        center = offset * 5 + 5000
        freq = channel * 5 + 5000
        res = [freq, width, center]
    except IndexError:
        print("Invalid channel width combo: (chan: {}, width: {})".format(channel, width))
        res = None
    except KeyError:
        print("Invalid Channel: {}".format(channel))
        res = None
    return res

def convert_6ghz_chan2freq(chan: int):
    return int(5950 + (5 * chan))

def get_6ghz_center_freq(chan: int, width: int):
    freq = convert_6ghz_chan2freq(chan)
    mod = int(width / 20)
    offset = int((width / 10) - 2)
    center_freq = freq - int(((((chan - 1) / 4) % mod) * 4 - offset) * 5)
    return center_freq

def get_6g_freq(chan: int, width: int):
    res = "freq: {} width: {} center_freq: {}"
    freq = convert_6ghz_chan2freq(chan)
    center_freq = get_6ghz_center_freq(chan, width)
    return freq, width, center_freq

def main():
    iw_cmd = "sudo iw mon0 set freq {} {} {}" #format(iface, freq, width, center_freq)
    res = None
    band = int(sys.argv[1])
    chan = int(sys.argv[2])
    width = int(sys.argv[3])

    if band == 2:
        res = get_2g_freq(chan, width)
    elif band == 5:
        res = get_5g_freq(chan, width)
    elif band == 6:
        res = get_6g_freq(chan, width)
    else:
        print("Usage: {} <[2|5|6]> <channel> <channel_width>".format(sys.argv[0]))
    if res is not None:
        if len(res) == 2:
            res = "sudo iw mon0 set freq {} {}".format(res[0], res[1])
        else:
            res = iw_cmd.format(res[0], res[1], res[2])
    return res

if __name__ == "__main__":
    res = main()
    print(res)