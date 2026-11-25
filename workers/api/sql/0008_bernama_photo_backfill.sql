-- Backfill the verified original BERNAMA photo for the article shown in GomoGie.
UPDATE gomogie_news_items
SET image_url='https://web14.bernama.com/storage/photos/2b7a901cdbdb1a3bc3506f40f4995b626b07091d129b3-large'
WHERE title='More Discourse-based Programes, Culture of Mature And Open Dialogues Must Be Organised - PM Anwar'
  AND (image_url IS NULL OR image_url='');
