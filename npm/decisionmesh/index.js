import { readFileSync } from 'node:fs';

const schemaText = readFileSync(new URL('./schemas/event.schema.json', import.meta.url), 'utf8');

/** Return exact schema JSON text, preserving integer precision. Not a validator. */
export function getEventSchemaText() {
  return schemaText;
}
