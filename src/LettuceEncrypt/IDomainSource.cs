// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Linq;
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
        /// Gets a collection of domains that will be consdered for creation/renewal.
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        Task<IEnumerable<IDomainCert>> GetDomains(CancellationToken cancellationToken);
    }

    public interface IDomainCert
    {
        public string PrimaryDomain { get; }
        public IEnumerable<string> Domains { get; }
    }

    public class SingleDomainCert : IDomainCert
    {
        public string PrimaryDomain { get; set; } = default!;

        public IEnumerable<string> Domains => new[] { PrimaryDomain };
    }

    public class MultipleDomainCert : IDomainCert
    {
        public string PrimaryDomain { get; set; } = default!;
        public SortedSet<string> AlternateDomains { get; set; } = default!;

        public IEnumerable<string> Domains
        {
            get
            {
                return (new[] { PrimaryDomain }).Union(AlternateDomains);
            }
        }
    }
}
