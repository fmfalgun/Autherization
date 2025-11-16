import { AbilityBuilder, createMongoAbility } from '@casl/ability';

/**
 * Define abilities for a user based on their role and attributes
 */
export function defineAbilitiesFor(user) {
  const { can, cannot, build } = new AbilityBuilder(createMongoAbility);

  if (!user) {
    // Guest users can only read public posts
    can('read', 'Post', { isPublic: true });
    return build();
  }

  // All authenticated users can read all posts
  can('read', 'Post');
  can('read', 'User');

  if (user.role === 'admin') {
    // Admins can do everything
    can('manage', 'all');
  } else if (user.role === 'editor') {
    // Editors can create posts
    can('create', 'Post');

    // Editors can update and delete their own posts
    can('update', 'Post', { authorId: user.id });
    can('delete', 'Post', { authorId: user.id });

    // Editors can update their own profile
    can('update', 'User', { id: user.id });
  } else if (user.role === 'viewer') {
    // Viewers can only read
    // (already granted above)
  }

  return build();
}

/**
 * Convert ability rules to plain object for sending to client
 */
export function packRules(ability) {
  return ability.rules;
}
