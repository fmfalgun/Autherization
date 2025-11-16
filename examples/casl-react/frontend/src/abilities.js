import { createMongoAbility } from '@casl/ability';

/**
 * Create ability instance from rules received from server
 */
export function buildAbilityFor(rules) {
  return createMongoAbility(rules || []);
}

/**
 * Default guest ability (no permissions)
 */
export const defaultAbility = createMongoAbility([
  { action: 'read', subject: 'Post', conditions: { isPublic: true } }
]);
