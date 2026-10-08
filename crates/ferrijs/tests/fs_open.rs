use ferrijs::{Permissions, RunOptions, Runtime};

#[tokio::test]
async fn read_write_handles_require_both_permissions() -> Result<(), Box<dyn std::error::Error>> {
  let dir = tempfile::tempdir()?;
  let path = dir.path().join("fixture.txt");
  std::fs::write(&path, "Salama")?;
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_write([dir.path()]))
    .build()
    .await?;
  for flag in ["r+", "rs+", "sr+", "a+", "ax+", "xa+", "as+", "sa+", "w+", "wx+", "xw+"] {
    let run = rt
      .eval_script(
        "const fs = require('node:fs/promises');
         try { const h = await fs.open(args[0], args[1]); await h.close(); return 'opened'; }
         catch (e) { return { code: e.code, permission: e.permission }; }",
        &[serde_json::json!(path), flag.into()],
        RunOptions::default(),
      )
      .await;
    assert_eq!(
      run.result?,
      serde_json::json!({ "code": "ERR_ACCESS_DENIED", "permission": "read" }),
      "{flag}"
    );
    assert_eq!(std::fs::read_to_string(&path)?, "Salama", "{flag}");
  }
  Ok(())
}

#[tokio::test]
async fn append_read_creates_and_exclusive_read_write_can_write() -> Result<(), Box<dyn std::error::Error>> {
  let dir = tempfile::tempdir()?;
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_read([dir.path()]).allow_write([dir.path()]))
    .build()
    .await?;
  for flag in ["a+", "ax+", "xa+", "wx+", "xw+"] {
    let path = dir.path().join(flag);
    let run = rt
      .eval_script(
        "const fs = require('node:fs/promises');
       const h = await fs.open(args[0], args[1]);
       try { await h.writeFile('Salama'); } finally { await h.close(); }
       return await fs.readFile(args[0], 'utf8');",
        &[serde_json::json!(path), flag.into()],
        RunOptions::default(),
      )
      .await;
    assert_eq!(run.result?, "Salama", "{flag}");
  }
  Ok(())
}

#[tokio::test]
async fn open_preserves_node_error_metadata() -> Result<(), Box<dyn std::error::Error>> {
  let dir = tempfile::tempdir()?;
  let path = dir.path().join("fixture.txt");
  std::fs::write(&path, "Salama")?;
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_read([dir.path()]).allow_write([dir.path()]))
    .build()
    .await?;
  for (path, flag, code) in [(path, "wx", "EEXIST"), (dir.path().join("missing"), "r", "ENOENT")] {
    let run = rt
      .eval_script(
        "try { const h = await require('node:fs/promises').open(args[0], args[1]); await h.close(); return null; }
       catch (e) { return { code: e.code, syscall: e.syscall, path: e.path, errno: e.errno < 0 }; }",
        &[serde_json::json!(path), flag.into()],
        RunOptions::default(),
      )
      .await;
    assert_eq!(
      run.result?,
      serde_json::json!({"code": code, "syscall": "open", "path": path, "errno": true})
    );
  }
  Ok(())
}

#[tokio::test]
async fn combined_access_modes_require_each_grant() -> Result<(), Box<dyn std::error::Error>> {
  let dir = tempfile::tempdir()?;
  let path = dir.path().join("fixture.txt");
  std::fs::write(&path, "Salama")?;
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_write([dir.path()]))
    .build()
    .await?;
  for source in [
    "const fs = require('node:fs'); try { fs.accessSync(args[0], fs.constants.R_OK | fs.constants.W_OK); return 'allowed'; } catch(e) { return e.code; }",
    "const fs = require('node:fs/promises'); try { await fs.access(args[0], fs.constants.R_OK | fs.constants.W_OK); return 'allowed'; } catch(e) { return e.code; }",
  ] {
    let run = rt
      .eval_script(source, &[serde_json::json!(path)], RunOptions::default())
      .await;
    assert_eq!(run.result?, "ERR_ACCESS_DENIED");
  }
  Ok(())
}

#[tokio::test]
async fn write_file_through_an_append_handle_appends() -> Result<(), Box<dyn std::error::Error>> {
  let dir = tempfile::tempdir()?;
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_read([dir.path()]).allow_write([dir.path()]))
    .build()
    .await?;
  for flag in ["a", "a+"] {
    let path = dir.path().join(flag);
    std::fs::write(&path, "Salama")?;
    let run = rt
      .eval_script(
        "const fs = require('node:fs/promises');
       const h = await fs.open(args[0], args[1]);
       try { await h.writeFile(' Ashoush'); } finally { await h.close(); }
       return await fs.readFile(args[0], 'utf8');",
        &[serde_json::json!(path), flag.into()],
        RunOptions::default(),
      )
      .await;
    assert_eq!(run.result?, "Salama Ashoush", "{flag}");
  }
  Ok(())
}

#[tokio::test]
async fn append_file_creates_the_file_then_extends_it() -> Result<(), Box<dyn std::error::Error>> {
  let dir = tempfile::tempdir()?;
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_read([dir.path()]).allow_write([dir.path()]))
    .build()
    .await?;
  let run = rt
    .eval_script(
      "const fs = require('node:fs'); const fsp = require('node:fs/promises');
       const [promised, synced] = args;
       await fsp.appendFile(promised, 'Salama');
       await fsp.appendFile(promised, Buffer.from(' Ashoush'));
       fs.appendFileSync(synced, new TextEncoder().encode('Salama'));
       fs.appendFileSync(synced, ' Ashoush');
       return [await fsp.readFile(promised, 'utf8'), fs.readFileSync(synced, 'utf8')];",
      &[
        serde_json::json!(dir.path().join("promised")),
        serde_json::json!(dir.path().join("synced")),
      ],
      RunOptions::default(),
    )
    .await;
  assert_eq!(run.result?, serde_json::json!(["Salama Ashoush", "Salama Ashoush"]));
  Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn append_file_mode_applies_only_when_it_creates() -> Result<(), Box<dyn std::error::Error>> {
  use std::os::unix::fs::PermissionsExt;

  let dir = tempfile::tempdir()?;
  let path = dir.path().join("created");
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_read([dir.path()]).allow_write([dir.path()]))
    .build()
    .await?;
  let run = rt
    .eval_script(
      "const fs = require('node:fs');
       fs.appendFileSync(args[0], 'Salama', { mode: 0o600 });
       await require('node:fs/promises').appendFile(args[0], ' Ashoush', { mode: 0o644 });
       return fs.readFileSync(args[0], 'utf8');",
      &[serde_json::json!(path)],
      RunOptions::default(),
    )
    .await;
  assert_eq!(run.result?, "Salama Ashoush");
  assert_eq!(std::fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
  Ok(())
}

#[tokio::test]
async fn append_file_needs_a_write_grant() -> Result<(), Box<dyn std::error::Error>> {
  let dir = tempfile::tempdir()?;
  let path = dir.path().join("denied");
  let rt = Runtime::builder()
    .permissions(Permissions::none().allow_read([dir.path()]))
    .build()
    .await?;
  let run = rt
    .eval_script(
      "const shape = e => [e.name, e.code, e.permission];
       const out = [];
       try { await require('node:fs/promises').appendFile(args[0], 'x'); out.push('allowed'); } catch (e) { out.push(shape(e)); }
       try { require('node:fs').appendFileSync(args[0], 'x'); out.push('allowed'); } catch (e) { out.push(shape(e)); }
       return out;",
      &[serde_json::json!(path)],
      RunOptions::default(),
    )
    .await;
  let denied = serde_json::json!(["PermissionDeniedError", "ERR_ACCESS_DENIED", "write"]);
  assert_eq!(run.result?, serde_json::json!([denied, denied]));
  assert!(!path.exists());
  Ok(())
}
