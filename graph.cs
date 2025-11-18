// To run this program and generate the bar graph image:
// 1. Create a new C# Console Project (.NET 6 or newer).
// 2. Install the necessary NuGet package:
//    > dotnet add package ScottPlot.WinForms
// 3. Uncomment the code block marked "SCOTTPLOT CHART GENERATION CODE".
// 4. Run the application (e.g., dotnet run). A file named 'throughput_comparison.png' 
//    will be generated in your project's bin/Debug/netX.0 directory.

using System;
using System.Drawing; // Required by ScottPlot for Color definition
using System.Linq;

// NOTE: The main plotting logic is commented out because it requires the ScottPlot 
// NuGet package to be installed. Uncomment the block below the data definition 
// after installation.

public class ThroughputComparer
{
    public static void Main(string[] args)
    {
        Console.WriteLine("--- Device Throughput Comparison Data ---");
        Console.WriteLine("Defining data for two devices across five distances (Rx/Tx throughput).");

        // 1. Data Definition
        // =========================================================================

        // The five distances used for the second X-axis label group
        string[] distanceLabels = { "5m", "10m", "15m", "20m", "25m" };
        int distanceGroups = distanceLabels.Length;
        
        // This array defines the Rx/Tx labels for the first X-axis
        string[] rxTxLabels = { "Rx", "Tx" };

        // The number of total data points (categories) is 5 distances * 2 (Rx/Tx) = 10
        int totalDataPoints = distanceGroups * rxTxLabels.Length;

        // Combine Rx and Tx labels for all 10 positions
        string[] categoryLabels = Enumerable.Range(0, distanceGroups)
            .SelectMany(_ => rxTxLabels)
            .ToArray();

        // Throughput data in Mbps (10 data points per device)
        // Order: (5m Rx, 5m Tx), (10m Rx, 10m Tx), ..., (25m Rx, 25m Tx)

        // Device 1: 'Alpha' (Blue)
        double[] throughputDeviceA = new double[]
        {
            // 5m: Rx, Tx
            850, 920,
            // 10m: Rx, Tx
            780, 850,
            // 15m: Rx, Tx
            650, 700,
            // 20m: Rx, Tx
            550, 580,
            // 25m: Rx, Tx
            420, 450
        };

        // Device 2: 'Beta' (Orange)
        double[] throughputDeviceB = new double[]
        {
            // 5m: Rx, Tx
            880, 950,
            // 10m: Rx, Tx
            810, 890,
            // 15m: Rx, Tx
            690, 750,
            // 20m: Rx, Tx
            590, 620,
            // 25m: Rx, Tx
            460, 490
        };

        // 2. Displaying sample data to the console
        // =========================================================================
        Console.WriteLine("\n| Distance | Metric | Alpha (Mbps) | Beta (Mbps) |");
        Console.WriteLine("|----------|--------|--------------|-------------|");
        
        for (int i = 0; i < totalDataPoints; i++)
        {
            int distanceIndex = i / rxTxLabels.Length;
            string distance = distanceLabels[distanceIndex];
            string metric = categoryLabels[i];
            
            Console.WriteLine($"| {distance.PadLeft(8)} | {metric.PadLeft(6)} | {throughputDeviceA[i].ToString().PadLeft(12)} | {throughputDeviceB[i].ToString().PadLeft(11)} |");
        }


        // 3. SCOTTPLOT CHART GENERATION CODE (UNCOMMENT AFTER PACKAGE INSTALLATION)
        // =========================================================================

        /*
        try
        {
            // 1. Initialize the Plot
            var plt = new ScottPlot.Plot(1000, 600);
            plt.Title("Device Throughput Comparison (Rx/Tx Grouped by Distance)");
            plt.YLabel("Throughput (Mbps)");
            
            // 2. Define Positions for the bars
            // Group bars are typically placed near integers: 0, 1, 2, 3, ... 9
            double[] positions = ScottPlot.DataGen.Consecutive(totalDataPoints);

            // 3. Add Bar Data (Device Alpha - Blue)
            var barA = plt.AddBar(throughputDeviceA, positions);
            barA.Label = "Device Alpha";
            barA.BarWidth = 0.4; // Width for the first set of bars
            barA.FillColor = Color.Blue; // Set bar color to blue
            barA.BorderColor = Color.Black;

            // 4. Add Bar Data (Device Beta - Orange)
            // Offset the position slightly to place the second bar next to the first
            double[] positionsOffset = positions.Select(p => p + barA.BarWidth).ToArray();
            var barB = plt.AddBar(throughputDeviceB, positionsOffset);
            barB.Label = "Device Beta";
            barB.BarWidth = 0.4; // Same width as the first set
            barB.FillColor = Color.Orange; // Set bar color to orange
            barB.BorderColor = Color.Black;

            // Adjust X-axis limits to center the groups
            plt.SetAxisLimits(yMin: 0, xMin: positions.First() - 0.5, xMax: positions.Last() + barB.BarWidth + 0.5);

            // 5. Configure the X-Axis Labels (Two Layers)
            
            // Layer 1: Rx/Tx Labels (first X-axis)
            // Center the tick marks between the two bars of each pair
            double[] tickPositions = positions.Select(p => p + barA.BarWidth / 2).ToArray();
            plt.XTicks(tickPositions, categoryLabels);

            // Layer 2: Distance Labels (second X-axis)
            // Calculate the position for the center of each distance group
            double[] groupPositions = Enumerable.Range(0, distanceGroups)
                .Select(i => (positions[i * 2] + positionsOffset[i * 2 + 1]) / 2) // Average of the 5m-Rx and 5m-Tx positions, etc.
                .ToArray();

            // Add the second, custom axis below the primary X-axis
            var xAxis2 = plt.AddAxis(ScottPlot.Renderable.Edge.Bottom, ScottPlot.Renderable.AxisType.Numeric, 1);
            xAxis2.Label.Text = "Distance";
            xAxis2.TickGenerator = new ScottPlot.TickGenerators.NumericManual(
                groupPositions.Select((pos, i) => new ScottPlot.Tick(pos, distanceLabels[i])).ToArray()
            );
            xAxis2.TickLabelStyle.Font.Size = 14;
            xAxis2.LineStyle.Color = Color.Black;
            xAxis2.LineStyle.Width = 2;


            // 6. Final Plot Configuration
            
            // Move the legend to the upper right corner
            plt.Legend(ScottPlot.Alignment.UpperRight); 

            // Improve aesthetics
            plt.Grid(lineStyle: ScottPlot.LineStyle.Dash, lineAlpha: 0.5);

            // 7. Save the Plot to a file
            string filename = "throughput_comparison.png";
            plt.SaveFig(filename);
            
            Console.WriteLine($"\nSuccessfully generated chart image: {filename}");
        }
        catch (TypeInitializationException ex)
        {
            Console.WriteLine("\n--- ScottPlot Initialization Error ---");
            Console.WriteLine("The chart generation failed. This usually means the 'ScottPlot.WinForms' package has not been installed.");
            Console.WriteLine("Please run 'dotnet add package ScottPlot.WinForms' in your project directory and uncomment the 'SCOTTPLOT CHART GENERATION CODE' block.");
            Console.WriteLine($"Error Details: {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\nAn unexpected error occurred: {ex.Message}");
        }
        */

        Console.WriteLine("\nProgram finished. If ScottPlot was installed, check the project directory for 'throughput_comparison.png'.");
    }
}


