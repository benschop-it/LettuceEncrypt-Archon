// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.Extensions.Hosting;

namespace LettuceEncrypt
{
    /// <summary>
    /// Service running state machine for cert loading and renewal
    /// </summary>
    public interface IAcmeCertificateLoader : IHostedService { }
}
