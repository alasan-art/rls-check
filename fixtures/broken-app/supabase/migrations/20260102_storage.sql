-- Invented demo: ID uploads in a public bucket, anyone can upload
insert into storage.buckets (id, name, public) values ('passports', 'passports', true), ('logos', 'logos', false);
create policy "upload passports" on storage.objects for insert to anon, authenticated with check (bucket_id = 'passports');
create policy "read passports" on storage.objects for select using (bucket_id = 'passports');
