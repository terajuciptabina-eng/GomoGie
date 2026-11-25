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

## Unified native content
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
- media_usage_records: media_asset_id, storage_bytes, delivery_bytes, processing_units, measured_at (operational cost accounting; do not expose private infrastructure details to ordinary users)
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

## Platform sustainability and optional commerce
- usage_quotas: plan_or_policy_key, resource_type, limit_value, period, effective_at (must represent transparent fair-use policy; do not imply unlimited usage)
- usage_events: user_id, resource_type, quantity, measured_at
- monetisation_placements: placement_type, status, disclosure_label, targeting_policy (future optional advertising/sponsorship; subject to privacy and legal review)
- optional_services: service_key, description, price, eligibility, status (future optional services only; never required for core participation)

## Design constraints
- Define uniqueness for handles, membership pairs, follows and reaction targets.
- Model audience visibility and deletion/retention explicitly.
- Avoid trusting client-supplied author IDs or role claims.
- Apply block/mute and community access rules consistently across feeds, search and notifications.
- Apply fair-use quotas consistently and explain user-facing limits clearly.
- Do not expose private messages or sensitive account data to analytics.
- Define deletion and export behaviour before production.


## Synthetic prototype fixtures
- demo_accounts: fixture records only; stable synthetic ID, fictional display name/handle, bio, public placeholder avatar URL, interests, synthetic flag and demo label.
- demo_posts: fixture records only; synthetic author reference, type, caption, media URL/thumbnail, source provider/page, illustrative engagement counts, timestamps and synthetic flag.
- Do not merge fixture data into production user tables.
- Add an explicit environment/configuration boundary before any production API is connected.

