# GomoGie — Conceptual Data Model

This is a domain-level starting point, not a final database schema. Fields, indexes, retention and access rules require security and product review before production.

## Core identity
- users: account identity, status, created_at, updated_at
- profiles: user_id, display_name, handle, bio, avatar_media_id, profile_visibility
- roles: role definitions
- user_roles: user_id, role_id, scope
- sessions: session metadata and revocation state (sensitive tokens must not be stored in plaintext)

## Social graph
- follows: follower_id, followed_id, created_at
- blocks: blocker_id, blocked_id, created_at
- mutes: muter_id, muted_id, created_at

## Unified content
- posts: author_id, content_type, body, audience, status, parent_post_id, created_at, updated_at
- post_media: post_id, media_id, position, alt_text
- comments: post_id, author_id, parent_comment_id, body, status, created_at
- reactions: actor_id, target_type, target_id, reaction_type, created_at
- reposts: actor_id, post_id, quote_text, created_at
- hashtags: normalized_tag
- post_hashtags: post_id, hashtag_id
- polls: post_id, closes_at
- poll_options: poll_id, label, position
- poll_votes: poll_id, option_id, user_id

## Media and video
- media_assets: owner_id, storage_key, media_type, processing_status, dimensions, duration, created_at
- channels: owner_id, title, description, visibility
- playlists: channel_id, title, visibility
- playlist_items: playlist_id, media_asset_id, position
- video_views: media_asset_id, viewer_id or privacy-safe anonymous key, viewed_at

## Communities
- communities: owner_id, name, slug, description, visibility, rules
- community_members: community_id, user_id, membership_role, status, joined_at
- community_posts: community_id, post_id

## Messaging
- conversations: conversation_type, created_by, created_at
- conversation_members: conversation_id, user_id, role, joined_at, last_read_at
- messages: conversation_id, sender_id, body, message_type, created_at, edited_at, deleted_at
- message_attachments: message_id, media_asset_id

## Notifications and trust & safety
- notifications: recipient_id, actor_id, event_type, target_type, target_id, read_at, created_at
- reports: reporter_id, target_type, target_id, reason, details, status, created_at
- moderation_actions: moderator_id, target_type, target_id, action, reason, created_at
- appeals: moderation_action_id, appellant_id, statement, status, created_at
- audit_logs: actor_id, action, resource_type, resource_id, created_at, metadata

## Design constraints
- Define uniqueness for handles, membership pairs, follows and reaction targets.
- Model audience visibility and deletion/retention explicitly.
- Avoid trusting client-supplied author IDs or role claims.
- Apply block/mute and community access rules consistently across feeds, search and notifications.
- Define deletion and export behaviour before production.
- Do not expose private messages or sensitive account data to analytics.
