using Xunit;
using Xunit.Sdk;

namespace ncryptf.Test.xunit
{
    [XunitTestCaseDiscoverer("ncryptf.Test.xunit.SkippableFactDiscoverer", "ncryptf.Test")]
    public class SkippableFactAttribute : FactAttribute { }
}