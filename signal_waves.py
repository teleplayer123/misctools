import matplotlib.pyplot as plt
import numpy as np
import os

class GraphWave:

    def __init__(self, x_arr, y_arr, **kwargs):
        self.xs = x_arr
        self.ys = y_arr
        self.kwargs = kwargs

    def save_graph(self, fig):
        if self.kwargs.get("save_dirname") != None:
            save_dir = self.kwargs.get("save_dirname")
            if not os.path.exists(save_dir):
                os.mkdir(save_dir)
        else:
            save_dir = os.path.join(os.getcwd(), "SignalWaveGraphs")
            if not os.path.exists(save_dir):
                os.mkdir(save_dir)

        if self.kwargs.get("save_filename") != None:
            fn = self.kwargs.get("save_filename")
            self.filename = os.path.join(save_dir, fn)
        else:
            self.filename = os.path.join(save_dir, "SignalWaveGraph.png")
        fig.save(self.filename)

    def plot_wave_fig(self):
        fig = plt.figure(figsize=(12, 10))
        plt.plot(self.xs, self.ys)
        plt.title("Signal Wave")
        plt.xlabel("Time")
        plt.ylabel("Amplitude")
        plt.grid(True)
        plt.show()

    def plot_wave(self):
        fig, ax = plt.subplots(figsize=(12, 8))
        ax.plot(self.xs, self.ys)
        plt.title("Signal Wave")
        plt.xlabel("Time")
        plt.ylabel("Amplitude")
        plt.grid(True)
        plt.show()


class SignalWaveGen:

    def __init__(self, x=None):
        if x is None:
            self.x = np.arange(0, 5*np.pi, 0.1)
        else:
            self.x = x

    def sine_wave(self, amplitude=0.1, periodicity=5):
        x = self.x
        y = amplitude * np.sin(periodicity * x)
        return x, y
    
    def signal_wave(self, freq=440, ampl=1.0, phase_offset=0):
        """
        freq: measure of cycles per second (Hz)
        ampl: measures strength of signal

        """
        x = self.x
        period = 1.0/freq
        ts = period * x
        phases = freq * 2 * np.pi * ts + phase_offset
        signal = ampl * np.sin(phases)
        return ts, signal
    

gen = SignalWaveGen()
x, y = gen.sine_wave()
g = GraphWave(x, y)
g.plot_wave()

ts = np.arange(1024)
gen = SignalWaveGen(ts)
x, y = gen.signal_wave()
g = GraphWave(x, y)
g.plot_wave()