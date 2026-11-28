-- Remove the retired feature schema and all stored options/votes.
-- Any empty content-only records associated with it were removed during the first cleanup run.
DROP TABLE IF EXISTS gomogie_poll_votes;
DROP TABLE IF EXISTS gomogie_poll_options;
DROP TABLE IF EXISTS gomogie_polls;
