// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace LettuceEncrypt
{
    /// <summary>
    /// Defines a source for domains that will be considered for creation/renewal
    /// </summary>
    public interface IDomainSource
    {
        /// <summary>
        /// Gets a collection of domains that will be consdered for creation/renewal. Certs are grouped by domain keys provided
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        Task<Dictionary<string, HashSet<string>>> GetDomainsAsync(CancellationToken cancellationToken);
    }
}
