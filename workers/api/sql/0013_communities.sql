-- Communities: additive only; preserve all existing GomoGie data.
CREATE TABLE IF NOT EXISTS communities (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 60),
  slug TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  visibility TEXT NOT NULL CHECK(visibility IN ('public','private','approval')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_communities_visibility_created ON communities(visibility,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_communities_owner ON communities(owner_id);
CREATE TABLE IF NOT EXISTS community_members (
  community_id TEXT NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  membership_role TEXT NOT NULL DEFAULT 'member' CHECK(membership_role IN ('owner','moderator','member')),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','pending','banned')),
  joined_at TEXT NOT NULL,
  PRIMARY KEY(community_id,user_id)
);
CREATE INDEX IF NOT EXISTS idx_community_members_user ON community_members(user_id,status);
CREATE INDEX IF NOT EXISTS idx_community_members_community ON community_members(community_id,status,membership_role);
CREATE TABLE IF NOT EXISTS community_posts (
  community_id TEXT NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  PRIMARY KEY(community_id,post_id)
);
CREATE INDEX IF NOT EXISTS idx_community_posts_feed ON community_posts(community_id,created_at DESC);
