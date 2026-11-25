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

CREATE TABLE IF NOT EXISTS community_rules (
  id TEXT PRIMARY KEY,
  community_id TEXT NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 100),
  body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 1000),
  position INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_community_rules_order ON community_rules(community_id,position);
CREATE TABLE IF NOT EXISTS community_events (
  id TEXT PRIMARY KEY,
  community_id TEXT NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  creator_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 100),
  description TEXT NOT NULL DEFAULT '',
  starts_at TEXT NOT NULL,
  location TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_community_events_start ON community_events(community_id,starts_at);
CREATE TABLE IF NOT EXISTS community_reports (
  id TEXT PRIMARY KEY,
  community_id TEXT NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
  reporter_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_type TEXT NOT NULL CHECK(target_type IN ('community','post','member')),
  target_id TEXT NOT NULL,
  reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 500),
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','reviewed','dismissed','actioned')),
  created_at TEXT NOT NULL,
  reviewed_by TEXT REFERENCES users(id),
  reviewed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_community_reports_queue ON community_reports(community_id,status,created_at DESC);
