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
