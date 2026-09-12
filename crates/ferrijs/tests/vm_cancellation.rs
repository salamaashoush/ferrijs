use std::sync::{
  Arc,
  atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use ferrijs::{RunOptions, Runtime};

struct Dropped(Arc<AtomicBool>);

impl Drop for Dropped {
  fn drop(&mut self) {
    self.0.store(true, Ordering::SeqCst);
  }
}

#[tokio::test]
async fn zero_capacity_is_rejected() {
  assert!(Runtime::builder().vm_capacity(0).build().await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_completed_job_releases_capacity_before_replying() -> Result<(), Box<dyn std::error::Error>> {
  let rt = Runtime::builder().vm_capacity(1).build().await?;
  for _ in 0..10_000 {
    rt.with(|_ctx| Box::pin(async {})).await?;
  }
  Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_admission_never_exceeds_capacity() -> Result<(), Box<dyn std::error::Error>> {
  let rt = Arc::new(Runtime::builder().vm_capacity(8).build().await?);
  let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
  let mut tasks = Vec::new();
  for _ in 0..128 {
    let rt = rt.clone();
    let tx = tx.clone();
    tasks.push(tokio::spawn(async move {
      let started = tx.clone();
      let result = rt
        .with(move |_ctx| {
          Box::pin(async move {
            let _ = started.send(true);
            std::future::pending::<()>().await;
          })
        })
        .await;
      if let Err(error) = result {
        assert!(error.message.contains("capacity exhausted"));
        let _ = tx.send(false);
      }
    }));
  }
  let admitted = tokio::time::timeout(Duration::from_secs(2), async {
    let mut admitted = 0;
    for _ in 0..128 {
      admitted += usize::from(rx.recv().await == Some(true));
    }
    admitted
  })
  .await?;
  assert_eq!(admitted, 8);
  for task in tasks {
    task.abort();
    if let Err(error) = task.await {
      assert!(error.is_cancelled());
    }
  }
  Ok(())
}

#[tokio::test]
async fn cancelling_a_queued_job_never_calls_its_body() -> Result<(), Box<dyn std::error::Error>> {
  let rt = Runtime::builder().build().await?;
  let called = Arc::new(AtomicBool::new(false));
  {
    let called = called.clone();
    let future = rt.with(move |_ctx| {
      Box::pin(async move {
        called.store(true, Ordering::SeqCst);
      })
    });
    let mut future = std::pin::pin!(future);
    assert!(futures::poll!(&mut future).is_pending());
  }
  rt.with(|_ctx| Box::pin(async {})).await?;
  assert!(!called.load(Ordering::SeqCst));
  Ok(())
}

#[tokio::test]
async fn cancelling_a_parked_job_drops_its_future() -> Result<(), Box<dyn std::error::Error>> {
  let rt = Arc::new(Runtime::builder().build().await?);
  let dropped = Arc::new(AtomicBool::new(false));
  let (started_tx, started_rx) = tokio::sync::oneshot::channel();
  let job = {
    let rt = rt.clone();
    let dropped = dropped.clone();
    tokio::spawn(async move {
      rt.with(move |_ctx| {
        Box::pin(async move {
          let _drop = Dropped(dropped);
          let _ = started_tx.send(());
          std::future::pending::<()>().await;
        })
      })
      .await
    })
  };
  started_rx.await?;
  job.abort();
  assert!(job.await.is_err_and(|error| error.is_cancelled()));
  rt.with(|_ctx| Box::pin(async {})).await?;
  assert!(dropped.load(Ordering::SeqCst));
  Ok(())
}

#[tokio::test]
async fn cancelling_a_run_poisons_the_realm() -> Result<(), Box<dyn std::error::Error>> {
  let rt = Runtime::builder().build().await?;
  let (started_tx, started_rx) = tokio::sync::oneshot::channel();
  let future = rt.run(
    RunOptions::default(),
    Box::new(move |_ctx| {
      Box::pin(async move {
        let _ = started_tx.send(());
        std::future::pending::<()>().await;
        Ok(())
      })
    }),
  );
  {
    let mut future = std::pin::pin!(future);
    tokio::select! {
      _ = &mut future => panic!("run completed before cancellation"),
      result = started_rx => result?,
      () = tokio::time::sleep(Duration::from_secs(2)) => panic!("run did not start"),
    }
  }
  assert!(rt.poisoned());
  assert!(
    rt.eval_script("return 1", &[], RunOptions::default())
      .await
      .result
      .is_err()
  );
  Ok(())
}

#[tokio::test]
async fn admission_bounds_active_jobs_and_recovers_after_cancellation() -> Result<(), Box<dyn std::error::Error>> {
  let rt = Arc::new(Runtime::builder().vm_capacity(2).build().await?);
  let mut tasks = Vec::new();
  for _ in 0..2 {
    let rt = rt.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tasks.push(tokio::spawn(async move {
      rt.with(move |_ctx| {
        Box::pin(async move {
          let _ = tx.send(());
          std::future::pending::<()>().await;
        })
      })
      .await
    }));
    rx.await?;
  }
  let rejected = rt.with(|_ctx| Box::pin(async {})).await;
  assert!(rejected.is_err_and(|error| error.message.contains("capacity exhausted")));
  for task in tasks {
    task.abort();
    assert!(task.await.is_err_and(|error| error.is_cancelled()));
  }
  tokio::time::timeout(Duration::from_secs(2), async {
    loop {
      if rt.with(|_ctx| Box::pin(async {})).await.is_ok() {
        break;
      }
      tokio::task::yield_now().await;
    }
  })
  .await?;
  Ok(())
}

#[tokio::test]
async fn a_parked_run_can_receive_a_reentrant_callback() -> Result<(), Box<dyn std::error::Error>> {
  let rt = Arc::new(Runtime::builder().vm_capacity(2).build().await?);
  let (started_tx, started_rx) = tokio::sync::oneshot::channel();
  let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
  let task = {
    let rt = rt.clone();
    tokio::spawn(async move {
      rt.run(
        RunOptions::default(),
        Box::new(move |_ctx| {
          Box::pin(async move {
            let _ = started_tx.send(());
            Ok(reply_rx.await.unwrap_or_default())
          })
        }),
      )
      .await
    })
  };
  started_rx.await?;
  rt.with(move |_ctx| {
    Box::pin(async move {
      let _ = reply_tx.send(42);
    })
  })
  .await?;
  let result = tokio::time::timeout(Duration::from_secs(2), task).await??;
  assert_eq!(result.result?, 42);
  assert!(!rt.poisoned());
  Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_interrupts_a_busy_script() -> Result<(), Box<dyn std::error::Error>> {
  let rt = Arc::new(Runtime::builder().build().await?);
  let (started_tx, started_rx) = tokio::sync::oneshot::channel();
  let task = {
    let rt = rt.clone();
    tokio::spawn(async move {
      rt.run(
        RunOptions {
          timeout: Some(Duration::from_secs(5)),
          ..RunOptions::default()
        },
        Box::new(move |ctx| {
          Box::pin(async move {
            let _ = started_tx.send(());
            ctx
              .eval::<(), _>("while (true) {}")
              .map_err(|error| ferrijs::ScriptError::internal(error.to_string()))
          })
        }),
      )
      .await
    })
  };
  started_rx.await?;
  task.abort();
  assert!(task.await.is_err_and(|error| error.is_cancelled()));
  assert!(rt.poisoned());
  tokio::time::timeout(Duration::from_secs(1), rt.with(|_ctx| Box::pin(async {}))).await??;
  Ok(())
}

#[tokio::test]
async fn rejected_runs_do_not_retarget_an_active_console() -> Result<(), Box<dyn std::error::Error>> {
  let rt = Arc::new(Runtime::builder().vm_capacity(1).build().await?);
  let (started_tx, started_rx) = tokio::sync::oneshot::channel();
  let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
  let task = {
    let rt = rt.clone();
    tokio::spawn(async move {
      rt.run(
        RunOptions::default(),
        Box::new(move |ctx| {
          Box::pin(async move {
            ctx
              .eval::<(), _>("console.log('before')")
              .map_err(|error| ferrijs::ScriptError::internal(error.to_string()))?;
            let _ = started_tx.send(());
            finish_rx
              .await
              .map_err(|error| ferrijs::ScriptError::internal(error.to_string()))?;
            ctx
              .eval::<(), _>("console.log('after')")
              .map_err(|error| ferrijs::ScriptError::internal(error.to_string()))
          })
        }),
      )
      .await
    })
  };
  started_rx.await?;
  let rejected = rt
    .eval_script(
      "return 1",
      &[],
      RunOptions {
        memory: Some(1),
        ..RunOptions::default()
      },
    )
    .await;
  assert!(
    rejected
      .result
      .is_err_and(|error| error.message.contains("capacity exhausted"))
  );
  assert!(!rt.poisoned());
  let _ = finish_tx.send(());
  let run = task.await?;
  run.result?;
  let messages: Vec<_> = run.console.iter().map(|entry| entry.message.as_str()).collect();
  assert_eq!(messages, ["before", "after"]);
  Ok(())
}
