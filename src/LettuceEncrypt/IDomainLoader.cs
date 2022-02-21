// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace LettuceEncrypt
{
    /// <summary>
    /// Defines the way to provide domains to have certificates generated.
    /// </summary>
    public interface IDomainLoader
    {
        /// <summary>
        /// Gets domains to manage certificates for.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <param name="domainNames">The domain names to get certificates for.</param>
        /// <param name="refreshCache">Force a cache refresh.</param>
        /// <returns>A collection of domains.</returns>
        Task<IEnumerable<IDomainCert>> GetDomainCertsAsync(CancellationToken cancellationToken, IEnumerable<string> domainNames, bool refreshCache = false);
    }
}
