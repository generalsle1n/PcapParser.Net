using SharpPcap;
using SharpPcap.LibPcap;

namespace PcapParser.Net;

public class PcapAnalyzer
{
    public string InputFile { get; init; }
    public string Filter { get; set; }
    public void ParsePcap()
    {
        using (CaptureFileReaderDevice Reader = new CaptureFileReaderDevice(InputFile))
        {
            Reader.Open(DeviceModes.None);
            Reader.Filter = ""
            Console.WriteLine();
        }
    }
}
public class Flow
