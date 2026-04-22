<p>Packages:</p>
<ul>
<li>
<a href="#lakom.extensions.gardener.cloud%2fv1alpha1">lakom.extensions.gardener.cloud/v1alpha1</a>
</li>
</ul>

<h2 id="lakom.extensions.gardener.cloud/v1alpha1">lakom.extensions.gardener.cloud/v1alpha1</h2>
<p>

</p>

<h3 id="lakomconfig">LakomConfig
</h3>


<p>
LakomConfig contains information about the Lakom service configuration.
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
<code>scope</code></br>
<em>
<a href="#scopetype">ScopeType</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The scope in which lakom will verify pods</p>
</td>
</tr>
<tr>
<td>
<code>trustedKeysResourceName</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>TrustedKeysResourceName is the name of the shoot resource providing additional cosign public keys for image signature validation.</p>
</td>
</tr>

</tbody>
</table>


