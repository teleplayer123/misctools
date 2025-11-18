// To run this program and generate the Excel chart file:
// 1. Create a new C# Console Project (.NET 6 or newer).
// 2. Install the necessary NuGet package:
//    > dotnet add package ClosedXML
// 3. Run the application (e.g., dotnet run). A file named 'Throughput_Comparison_ClosedXML.xlsx' 
//    will be generated in your project's bin/Debug/netX.0 directory.

using System;
using System.IO;
using ClosedXML.Excel;
using System.Linq;

public class ThroughputComparerClosedXML
{
    public static void Main(string[] args)
    {
        Console.WriteLine("--- Generating Excel Throughput Comparison Chart (using ClosedXML) ---");

        // 1. Data Definition
        // ===============================================================

        // 5 Distances: 5m, 10m, 15m, 20m, 25m
        string[] distanceLabels = { "5m", "10m", "15m", "20m", "25m" };
        int distanceGroups = distanceLabels.Length;

        // Rx/Tx Labels (Metric)
        string[] rxTxLabels = { "Rx", "Tx" };
        
        // Total rows in the data table will be 5 distances * 2 metrics = 10 rows
        int rowCount = distanceGroups * rxTxLabels.Length;

        // Data arrays for export
        string[] allDistances = new string[rowCount];
        string[] allMetrics = new string[rowCount];
        double[] throughputDeviceA = new double[rowCount];
        double[] throughputDeviceB = new double[rowCount];

        // Sample Throughput data in Mbps
        double[] dataA = new double[] { 850, 920, 780, 850, 650, 700, 550, 580, 420, 450 };
        double[] dataB = new double[] { 880, 950, 810, 890, 690, 750, 590, 620, 460, 490 };

        // Populate the export arrays
        for (int i = 0; i < rowCount; i++)
        {
            int distanceIndex = i / rxTxLabels.Length;
            allDistances[i] = distanceLabels[distanceIndex];
            allMetrics[i] = rxTxLabels[i % rxTxLabels.Length];
            throughputDeviceA[i] = dataA[i];
            throughputDeviceB[i] = dataB[i];
        }

        // 2. Excel File Generation
        // ===============================================================
        string filename = "Throughput_Comparison_ClosedXML.xlsx";
        
        // Delete existing file if it exists
        if (File.Exists(filename))
        {
            File.Delete(filename);
        }

        using (var workbook = new XLWorkbook())
        {
            var worksheet = workbook.Worksheets.Add("Throughput Data");
            int dataStartRow = 2; // Start data at row 2
            int dataEndRow = dataStartRow + rowCount - 1;

            // Add Table Headers (Row 1)
            worksheet.Cell("A1").Value = "Distance"; 
            worksheet.Cell("B1").Value = "Metric (Rx/Tx)";
            worksheet.Cell("C1").Value = "Device Alpha (Mbps)";
            worksheet.Cell("D1").Value = "Device Beta (Mbps)";
            
            // Apply formatting to headers
            worksheet.Row(1).Style.Font.SetBold();

            // Write Data to Spreadsheet
            for (int i = 0; i < rowCount; i++)
            {
                int currentRow = dataStartRow + i;
                worksheet.Cell(currentRow, 1).Value = allDistances[i];
                worksheet.Cell(currentRow, 2).Value = allMetrics[i];
                worksheet.Cell(currentRow, 3).Value = throughputDeviceA[i];
                worksheet.Cell(currentRow, 4).Value = throughputDeviceB[i];
            }

            // Auto-fit columns for readability
            worksheet.ColumnsUsed().AdjustToContents();

            // 3. Create the Clustered Column Chart
            
            // Define chart placement (E2 to N20)
            var chart = worksheet.AddChart<XLChart>(dataStartRow - 1, 5, 20, 15);
            chart.Title.Text = "Throughput Comparison: Rx/Tx Grouped by Distance";
            chart.Type = XLChartType.ColumnClustered;

            // 4. Configure Data Series (ClosedXML uses colors from standard Excel themes, 
            // but we can enforce them using hexadecimal codes).
            
            // Hex codes for Blue and Orange (corresponding to your request)
            string colorBlue = "#0070C0"; // Standard Office Blue
            string colorOrange = "#FFC000"; // Standard Office Orange

            // Series 1: Device Alpha (Blue)
            var series1 = chart.AddSeries();
            series1.NameFormula = worksheet.Cell("C1").Address.ToString(XLReferenceStyle.A1); // Name from C1
            series1.Values = worksheet.Range($"C{dataStartRow}:C{dataEndRow}"); // Data values
            series1.Fill.SetAutomaticSeriesColor(false);
            series1.Fill.SetColor(XLColor.FromHtml(colorBlue));
            series1.Border.SetColor(XLColor.Black);

            // Series 2: Device Beta (Orange)
            var series2 = chart.AddSeries();
            series2.NameFormula = worksheet.Cell("D1").Address.ToString(XLReferenceStyle.A1); // Name from D1
            series2.Values = worksheet.Range($"D{dataStartRow}:D{dataEndRow}"); // Data values
            series2.Fill.SetAutomaticSeriesColor(false);
            series2.Fill.SetColor(XLColor.FromHtml(colorOrange));
            series2.Border.SetColor(XLColor.Black);

            // 5. Configure Axes and Legend
            
            // Set the Category Axis (X-Axis) to use the two category columns for the dual labels.
            // This is the key to getting the grouped labels (Distance as the outer group, Rx/Tx as the inner)
            chart.Axes.Get(XLAxisPosition.Bottom)
                .SetCategories(worksheet.Range($"A{dataStartRow}:B{dataEndRow}"));
            
            // Set the Value Axis (Y-Axis) title
            chart.Axes.Get(XLAxisPosition.Left).Title.Text = "Throughput (Mbps)";

            // Legend (Upper Right Corner)
            chart.Legend.Position = XLLegendPosition.TopRight;

            // Save the file
            workbook.SaveAs(filename);
            Console.WriteLine($"\nSuccessfully generated Excel file: {Path.GetFullPath(filename)}");
        }
    }
}


