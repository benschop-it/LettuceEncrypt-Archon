// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Runtime.InteropServices;
using McMaster.Extensions.Xunit;

namespace LettuceEncrypt.UnitTests;

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
internal class SkipOnMacOSCIBuildAttribute : Attribute, ITestCondition
{
    public bool IsMet => string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CI"))
                         || !RuntimeInformation.IsOSPlatform(OSPlatform.OSX);

    public string SkipReason { get; set; }
}
