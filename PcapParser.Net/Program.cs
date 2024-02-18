using System.CommandLine;
using System.Globalization;
using System.Text.Json;
using CsvHelper;
using PcapParser.Net;

RootCommand Root = new RootCommand();

Command GetDistinct = new Command(name: "--Distinct", description: "Get distinct LAN to WAN Access");
Option<string[]> LanFilter = new Option<string[]>(name: "--LanFilter", description: "How to Specify Lan");
LanFilter.SetDefaultValue(new string[] { "src net 10.0.0.0/8", "src net 172.16.0.0/12", "src net 192.168.0.0/16" });

Option<string> InputFile = new Option<string>(name: "--File", description: "Enter File")
{
    IsRequired = true
};

Option<string> ExcludeFilter = new Option<string>(name: "--Exclude", description: "Enter Filter to Exclude (PcapFilter Expression: src host not 192.168.1.1)");
Option<string> OutputPath = new Option<string>(name: "--Output", description: "Enter the Path where the File should be saved")
{
    IsHidden = true
};
Option<SaveType> SaveTypeFormat = new Option<SaveType>(name: "--Type", description: "Enter the Type in which foramt the output should be saved")
{
    IsHidden = true
};
SaveTypeFormat.SetDefaultValue(SaveType.JSON);

GetDistinct.AddOption(LanFilter);
GetDistinct.AddOption(InputFile);
GetDistinct.AddOption(ExcludeFilter);
GetDistinct.AddOption(OutputPath);
GetDistinct.AddOption(SaveTypeFormat);


GetDistinct.SetHandler((InputLanFilter, InputFile, InputExclude, InputOutPath, InputSaveTypeFormat) =>
{
    PcapAnalyzer Pcap = new PcapAnalyzer()
    {
        InputFile = InputFile,
        Filter = InputLanFilter,
        Exclude = InputExclude
    };
    List<NetFlow> Flow = Pcap.ParsePcap();

    if (InputOutPath is null)
    {
        Pcap.PrintFlow(Flow);
    }
    else if (InputSaveTypeFormat == SaveType.JSON)
    {
        string Content = JsonSerializer.Serialize(Flow);
        File.WriteAllText(InputOutPath, Content);
    }
    else if (InputSaveTypeFormat == SaveType.CSV)
    {
        using (StreamWriter SWriter = new StreamWriter(InputOutPath))
        using (CsvWriter CWriter = new CsvWriter(SWriter, CultureInfo.InvariantCulture))
        {
            CWriter.WriteRecords(Flow);
        }
    }

}, LanFilter, InputFile, ExcludeFilter, OutputPath, SaveTypeFormat);

Root.AddCommand(GetDistinct);

await Root.InvokeAsync(args);