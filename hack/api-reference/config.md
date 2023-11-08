<p>Packages:</p>
<ul>
<li>
<a href="#lakom.extensions.config.gardener.cloud%2fv1alpha1">lakom.extensions.config.gardener.cloud/v1alpha1</a>
</li>
</ul>
<h2 id="lakom.extensions.config.gardener.cloud/v1alpha1">lakom.extensions.config.gardener.cloud/v1alpha1</h2>
<p>
<p>Package v1alpha1 contains the Lakom Shoot Service extension configuration.</p>
</p>
Resource Types:
<ul><li>
<a href="#lakom.extensions.config.gardener.cloud/v1alpha1.Configuration">Configuration</a>
</li></ul>
<h3 id="lakom.extensions.config.gardener.cloud/v1alpha1.Configuration">Configuration
</h3>
<p>
<p>Configuration contains information about the Lakom service configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>apiVersion</code></br>
string</td>
<td>
<code>
lakom.extensions.config.gardener.cloud/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>Configuration</code></td>
</tr>
<tr>
<td>
<code>healthCheckConfig</code></br>
<em>
github.com/gardener/gardener/extensions/pkg/apis/config/v1alpha1.HealthCheckConfig
</em>
</td>
<td>
<em>(Optional)</em>
<p>HealthCheckConfig is the config for the health check controller.</p>
</td>
</tr>
<tr>
<td>
<code>cosignPublicKeys</code></br>
<em>
[]string
</em>
</td>
<td>
<p>CosignPublicKeys is the cosign public keys used to verify image signatures.</p>
</td>
</tr>
<tr>
<td>
<code>failurePolicy</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>FailurePolicy is the failure policy used to configure the failurePolicy of the lakom admission webhooks.</p>
</td>
</tr>
<tr>
<td>
<code>debugConfig</code></br>
<em>
<a href="#lakom.extensions.config.gardener.cloud/v1alpha1.DebugConfig">
DebugConfig
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>DebugConfig contains debug configurations for the controller.</p>
</td>
</tr>
<tr>
<td>
<code>seedBootstrap</code></br>
<em>
<a href="#lakom.extensions.config.gardener.cloud/v1alpha1.SeedBootstrap">
SeedBootstrap
</a>
</em>
</td>
<td>
<p>SeedBootstrap configures the seed bootstrap controller.</p>
</td>
</tr>
<tr>
<td>
<code>useOnlyImagePullSecrets</code></br>
<em>
bool
</em>
</td>
<td>
<p>UseOnlyImagePullSecrets sets lakom to use only the image pull secrets of the pod to access the OCI registry.
Otherwise, also the node identity and docker config file are used.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="lakom.extensions.config.gardener.cloud/v1alpha1.DebugConfig">DebugConfig
</h3>
<p>
(<em>Appears on:</em>
<a href="#lakom.extensions.config.gardener.cloud/v1alpha1.Configuration">Configuration</a>)
</p>
<p>
<p>DebugConfig contains debug configurations for the controller.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enableProfiling</code></br>
<em>
bool
</em>
</td>
<td>
<p>EnableProfiling enables profiling via web interface host:port/debug/pprof/.</p>
</td>
</tr>
<tr>
<td>
<code>enableContentionProfiling</code></br>
<em>
bool
</em>
</td>
<td>
<p>EnableContentionProfiling enables lock contention profiling, if
enableProfiling is true.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="lakom.extensions.config.gardener.cloud/v1alpha1.SeedBootstrap">SeedBootstrap
</h3>
<p>
(<em>Appears on:</em>
<a href="#lakom.extensions.config.gardener.cloud/v1alpha1.Configuration">Configuration</a>)
</p>
<p>
<p>SeedBootstrap holds configurations for the seed bootstrap controller.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>ownerNamespace</code></br>
<em>
string
</em>
</td>
<td>
<p>OwnerNamespace is the name of the namespace owning the resources related
to the seed bootstrap, as well as where the managed resources are deployed.</p>
</td>
</tr>
</tbody>
</table>
<hr/>
<p><em>
Generated with <a href="https://github.com/ahmetb/gen-crd-api-reference-docs">gen-crd-api-reference-docs</a>
</em></p>
