using System.CommandLine;
using PcapParser.Net;

RootCommand Root = new RootCommand();

Command GetDistinct = new Command(name: "--Distinct", description: "Get distinct LAN to WAN Access");
Option<string[]> LanFilter = new Option<string[]>(name: "--LanFilter", description: "How to Specify Lan");
LanFilter.SetDefaultValue(new string[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" });

Option<string> InputFile = new Option<string>(name: "--File", description: "Enter File");

GetDistinct.AddOption(LanFilter);
GetDistinct.AddOption(InputFile);

GetDistinct.SetHandler((InputLanFilter, InputFile) =>
{
    PcapAnalyzer Pcap = new PcapAnalyzer()
    {
        InputFile = InputFile
    };
}, LanFilter, InputFile);

Root.AddCommand(GetDistinct);

PcapAnalyzer Pcap = new PcapAnalyzer()
{
    InputFile = "/home/niels/Schreibtisch/Data.pcap.ng"
};
Pcap.ParsePcap();

await Root.InvokeAsync(args);