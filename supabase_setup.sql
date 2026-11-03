-- 张小年的工作台：Supabase 云同步初始化
-- 请在 Supabase Dashboard -> SQL Editor 中一次性运行本文件。

create table if not exists public.workbench_states (
  user_id uuid primary key references auth.users(id) on delete cascade,
  data jsonb not null,
  revision bigint not null default 1 check (revision > 0),
  updated_at timestamptz not null default now(),
  device_id text
);

create table if not exists public.workbench_versions (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  revision bigint not null,
  data jsonb not null,
  created_at timestamptz not null default now(),
  device_id text
);

create index if not exists workbench_versions_user_created_idx
  on public.workbench_versions(user_id, created_at desc);

alter table public.workbench_states enable row level security;
alter table public.workbench_versions enable row level security;

drop policy if exists "read own workbench state" on public.workbench_states;
create policy "read own workbench state"
  on public.workbench_states for select to authenticated
  using ((select auth.uid()) = user_id);

drop policy if exists "read own workbench versions" on public.workbench_versions;
create policy "read own workbench versions"
  on public.workbench_versions for select to authenticated
  using ((select auth.uid()) = user_id);

-- 前端只能读取；写入统一经过下面的安全函数，避免并发覆盖。
revoke all on public.workbench_states from anon, authenticated;
revoke all on public.workbench_versions from anon, authenticated;
grant select on public.workbench_states to authenticated;
grant select on public.workbench_versions to authenticated;

create or replace function public.save_workbench(
  p_expected_revision bigint,
  p_data jsonb,
  p_device_id text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_uid uuid := auth.uid();
  v_current public.workbench_states%rowtype;
  v_new_revision bigint;
  v_updated_at timestamptz;
begin
  if v_uid is null then
    raise exception 'AUTH_REQUIRED';
  end if;

  if p_data is null or jsonb_typeof(p_data) <> 'object' then
    raise exception 'INVALID_DATA';
  end if;

  select * into v_current
  from public.workbench_states
  where user_id = v_uid
  for update;

  if not found then
    if p_expected_revision <> 0 then
      raise exception 'SYNC_CONFLICT';
    end if;

    insert into public.workbench_states(user_id, data, revision, updated_at, device_id)
    values (v_uid, p_data, 1, now(), p_device_id)
    returning revision, updated_at into v_new_revision, v_updated_at;

    return jsonb_build_object('revision', v_new_revision, 'updated_at', v_updated_at);
  end if;

  if v_current.revision <> p_expected_revision then
    raise exception 'SYNC_CONFLICT';
  end if;

  insert into public.workbench_versions(user_id, revision, data, device_id)
  values (v_uid, v_current.revision, v_current.data, v_current.device_id);

  update public.workbench_states
  set data = p_data,
      revision = v_current.revision + 1,
      updated_at = now(),
      device_id = p_device_id
  where user_id = v_uid
  returning revision, updated_at into v_new_revision, v_updated_at;

  delete from public.workbench_versions
  where user_id = v_uid
    and id not in (
      select id from public.workbench_versions
      where user_id = v_uid
      order by created_at desc
      limit 30
    );

  return jsonb_build_object('revision', v_new_revision, 'updated_at', v_updated_at);
end;
$$;

revoke all on function public.save_workbench(bigint, jsonb, text) from public, anon;
grant execute on function public.save_workbench(bigint, jsonb, text) to authenticated;
