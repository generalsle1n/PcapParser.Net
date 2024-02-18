using System.CommandLine;
using PcapParser.Net;

RootCommand Root = new RootCommand();

Command GetDistinct = new Command(name: "--Distinct", description: "Get distinct LAN to WAN Access");
Option<string[]> LanFilter = new Option<string[]>(name: "--LanFilter", description: "How to Specify Lan");
LanFilter.SetDefaultValue(new string[] { "src net 10.0.0.0/8", "src net 172.16.0.0/12", "src net 192.168.0.0/16" });

Option<string> InputFile = new Option<string>(name: "--File", description: "Enter File")
{
    IsRequired = true
};

GetDistinct.AddOption(LanFilter);
GetDistinct.AddOption(InputFile);

GetDistinct.SetHandler((InputLanFilter, InputFile) =>
{
    PcapAnalyzer Pcap = new PcapAnalyzer()
    {
        InputFile = InputFile,
        Filter = InputLanFilter
    };
    Pcap.ParsePcap();
}, LanFilter, InputFile);

Root.AddCommand(GetDistinct);

await Root.InvokeAsync(args);