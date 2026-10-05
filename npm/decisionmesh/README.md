# Decision Mesh

**Bootstrap prerelease: event schema tools for integration developers.**

Decision Mesh is an open-source project for making AI-agent decision requests visible and understandable. This npm release provides the version-one **structural event JSON Schema**, a lossless JavaScript text reader, and a command to export it for editors, form tooling, and adapter development.

The standalone application is still under development. This package does **not** install or run its dashboard, capture host requests, send notifications, store credentials, grant permissions, or resume agents. Native-host support and a production-ready application are not claimed by this prerelease. Progress Mesh integration is planned for a later release.

## Install and use

```sh
npm install decisionmesh@bootstrap
npx decisionmesh-schema event > decisionmesh-event.schema.json
```

```js
import { getEventSchemaText } from 'decisionmesh';

const schemaJson = getEventSchemaText(); // exact JSON text, including large integer limits
console.log(schemaJson);
```

The schema is also exported at `decisionmesh/event.schema.json`. The CLI accepts `event`, `--help`, and `--version`. It only reads bundled files and writes to standard output/error. It makes no network requests and does not read project data or credentials. There are no package dependencies or install scripts. Requires Node.js 22 or newer; the initial artifact was tested on Windows with Node.js 25.2.1.

## Validation and authority limits

This is the structural schema generated from Decision Mesh's Python event contracts. It is **not a complete event validator**: custom runtime checks are not expressible in the generated schema, including cross-field provenance rules, source authority and enrollment, native identity correlation, capture age, byte limits, and other semantic checks. The text API and CLI preserve numeric literals exactly. Some numeric fields exceed JavaScript's exact integer range; consumers must preserve their integer precision and must not silently round them.

Schema acceptance never means that a source is trusted, a user saw a prompt, permission was granted, an event was accepted by the application, or an agent resumed. Use the application's authoritative validation and source-registration boundary when that application is released; do not write straight into its private state. Prerelease schemas may change. Pin an exact version for repeatable integration experiments.

## Project

Source: [UniversalWinner/DecisionMesh](https://github.com/UniversalWinner/DecisionMesh)

License: MIT. This distribution contains only schemas, the small schema API/CLI, this README, and the license. No local workspace records, internal research, credentials, or notification content are included.
