//! `fs.realpathSync` and `fs.promises.realpath`: the path as the
//! operating system resolves it, behind the read grant every other read
//! is behind, with Node's error shape when it cannot be resolved.

use ferrijs::{Permissions, RunOptions, Runtime};

const BOTH: &str = "const fs = require('node:fs');
  const shape = e => ({ code: e.code, syscall: e.syscall, path: e.path, permission: e.permission, name: e.name });
  const sync = (() => { try { return fs.realpathSync(args[0]); } catch (e) { return shape(e); } })();
  const promised = await fs.promises.realpath(args[0]).catch(shape);
  return { sync, promised };";

async fn both(rt: &Runtime, path: &std::path::Path) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
  let run = rt
    .eval_script(BOTH, &[serde_json::json!(path)], RunOptions::default())
    .await;
  Ok(run.result?)
}

#[tokio::test]
async fn a_path_is_answered_as_the_system_resolves_it() -> Result<(), Box<dyn std::error::Error>> {
  let dir = tempfile::tempdir()?;
  let root = dunce::canonicalize(dir.path())?;
  std::fs::create_dir(root.join("inner"))?;
  std::fs::write(root.join("inner/real.txt"), "Salama")?;
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_read([root.as_path()]))
    .build()
    .await?;

  let real = serde_json::json!(root.join("inner/real.txt"));
  assert_eq!(
    both(&rt, &root.join("inner/../inner/./real.txt")).await?,
    serde_json::json!({ "sync": real, "promised": real })
  );

  #[cfg(unix)]
  {
    std::os::unix::fs::symlink(root.join("inner"), root.join("alias"))?;
    assert_eq!(
      both(&rt, &root.join("alias/real.txt")).await?,
      serde_json::json!({ "sync": real, "promised": real })
    );
  }

  let source = "import { realpathSync } from 'node:fs';
     import { realpath } from 'node:fs/promises';
     export default [realpathSync(FILE), await realpath(FILE, 'utf8'), await realpath(FILE, { encoding: 'utf8' })];"
    .replace("FILE", &real.to_string());
  let named = rt
    .eval_module_source("main.mjs", &source, &[], RunOptions::default())
    .await;
  assert_eq!(named.result?, serde_json::json!([real, real, real]));
  Ok(())
}

#[tokio::test]
async fn a_path_that_does_not_exist_fails_as_it_does_in_node() -> Result<(), Box<dyn std::error::Error>> {
  let dir = tempfile::tempdir()?;
  let root = dunce::canonicalize(dir.path())?;
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_read([root.as_path()]))
    .build()
    .await?;
  let missing = root.join("nope.txt");
  let failure =
    |syscall: &str| serde_json::json!({ "code": "ENOENT", "syscall": syscall, "path": missing, "name": "Error" });
  assert_eq!(
    both(&rt, &missing).await?,
    serde_json::json!({ "sync": failure("lstat"), "promised": failure("realpath") })
  );
  Ok(())
}

#[tokio::test]
async fn resolving_needs_the_read_grant_of_where_the_path_leads() -> Result<(), Box<dyn std::error::Error>> {
  let granted = tempfile::tempdir()?;
  let outside = tempfile::tempdir()?;
  let granted_root = dunce::canonicalize(granted.path())?;
  let outside_root = dunce::canonicalize(outside.path())?;
  std::fs::write(outside_root.join("secret.txt"), "Salama")?;
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_read([granted_root.as_path()]))
    .build()
    .await?;
  let direct = outside_root.join("secret.txt");
  let answered = both(&rt, &direct).await?;
  assert_eq!(answered["sync"]["code"], "ERR_ACCESS_DENIED", "{answered}");
  assert_eq!(answered["promised"]["permission"], "read", "{answered}");

  // A link inside the granted directory does not carry the grant out of it.
  #[cfg(unix)]
  {
    let link = granted_root.join("way-out");
    std::os::unix::fs::symlink(&direct, &link)?;
    let answered = both(&rt, &link).await?;
    assert_eq!(answered["sync"]["code"], "ERR_ACCESS_DENIED", "{answered}");
    assert_eq!(answered["promised"]["code"], "ERR_ACCESS_DENIED", "{answered}");
  }
  Ok(())
}

#[tokio::test]
async fn a_buffer_answer_is_refused() -> Result<(), Box<dyn std::error::Error>> {
  let dir = tempfile::tempdir()?;
  let root = dunce::canonicalize(dir.path())?;
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_read([root.as_path()]))
    .build()
    .await?;
  let run = rt
    .eval_script(
      "const fs = require('node:fs');
       const name = f => { try { f(); return 'returned'; } catch (e) { return e.name; } };
       return [
         name(() => fs.realpathSync(args[0], 'buffer')),
         name(() => fs.realpathSync(args[0], { encoding: 'buffer' })),
         await fs.promises.realpath(args[0], 'buffer').then(() => 'returned', e => e.name),
       ];",
      &[serde_json::json!(root)],
      RunOptions::default(),
    )
    .await;
  assert_eq!(run.result?, serde_json::json!(["TypeError", "TypeError", "TypeError"]));
  Ok(())
}
