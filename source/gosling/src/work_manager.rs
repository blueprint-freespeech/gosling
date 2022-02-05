// std
use std::default::Default;
use std::vec::Vec;
use std::sync::*;
use std::sync::atomic::*;
use std::thread;

// crates
use anyhow::{bail, Result};

struct Task {
    // closure
    closure : Box<dyn Fn() -> Result<()> + Send + 'static>,
}

pub struct WorkManager<const WORKER_COUNT: usize> {
    // shared queues of tasks
    producer_queues: [Arc<Mutex<Vec<Task>>>; WORKER_COUNT],

    // worker thread handles
    threads: [Option<thread::JoinHandle::<()>>; WORKER_COUNT],

    // condition varibales used to suspend worker threads when
    // they run out of work
    suspend_handles: [Arc<Condvar>; WORKER_COUNT],

    // set to true to indicate the worker threads need to finish up
    terminating: Arc<AtomicBool>,

    // the total number of pending tasks in the queues
    pending_tasks: Arc<AtomicUsize>,
}

impl<const WORKER_COUNT: usize> WorkManager<WORKER_COUNT> {
    pub fn new() -> Result<Self> {
        unsafe {
            // default initialize our various arrays
            let mut producer_queues: [Arc<Mutex<Vec<Task>>>; WORKER_COUNT] = std::mem::uninitialized();
            let mut threads: [Option<thread::JoinHandle::<()>>; WORKER_COUNT] = std::mem::uninitialized();
            let mut suspend_handles: [Arc<Condvar>; WORKER_COUNT] = std::mem::uninitialized();

            for worker_id in 0..WORKER_COUNT {
                std::ptr::write(&mut producer_queues[worker_id], Default::default());
                std::ptr::write(&mut threads[worker_id], Default::default());
                std::ptr::write(&mut suspend_handles[worker_id], Default::default());
            }

            // terminating signal is not set
            let terminating = Arc::new(AtomicBool::new(false));
            // start with no tasks
            let pending_tasks = Arc::new(AtomicUsize::new(0));

            return Ok(
                WorkManager::<WORKER_COUNT>{
                    producer_queues: producer_queues,
                    threads: threads,
                    suspend_handles: suspend_handles,
                    terminating: terminating,
                    pending_tasks: pending_tasks
                });
        }
    }

    pub fn start(&mut self, worker_names: &[&str; WORKER_COUNT]) -> Result<()> {
        for worker_id in 0..WORKER_COUNT {
            let worker_name = worker_names[worker_id].to_string();
            let producer_queue = self.producer_queues[worker_id].clone();
            let suspend_handle = self.suspend_handles[worker_id].clone();
            let terminating = self.terminating.clone();
            let pending_tasks = self.pending_tasks.clone();

            let thread = thread::Builder::new()
                .name(worker_name)
                .spawn(move || {
                    Self::worker_func(producer_queue, suspend_handle, terminating, pending_tasks);
                })?;

            self.threads[worker_id] = Some(thread);
        }

        return Ok(());
    }

    pub fn push<F: Fn() -> Result<()> + Send + 'static>(&mut self, worker_id: usize, closure: F) -> Result<()> {

        if worker_id >= WORKER_COUNT {
            bail!("WorkManager::push(): worker_id must be less than '{}'; received '{}'", WORKER_COUNT, worker_id);
        }

        // update the total pending task counter first
        self.pending_tasks.fetch_add(1, Ordering::Relaxed);

        // add task to work queue
        let task = Task{closure: Box::new(closure)};
        self.producer_queues[worker_id].lock().unwrap().push(task);

        // wake up worker thread
        self.suspend_handles[worker_id].notify_one();

        return Ok(());
    }

    pub fn join(&mut self) -> Result<()> {
        // signals to threads that they may now terminate
        self.terminating.store(true, Ordering::Relaxed);

        // wait for all of our threads to finish
        for i in 0..WORKER_COUNT {
            if self.threads[i].is_some() {
                // wake up this thread
                self.suspend_handles[i].notify_one();
                // wait for it to complete
                match self.threads[i].take().unwrap().join() {
                    Ok(_) => {},
                    Err(_) => {
                        panic!("WorkManager::join(): Error when joining threads");
                    },
                }
            }
        }

        return Ok(());
    }

    fn worker_func(producer_queue: Arc<Mutex<Vec<Task>>>, suspend_handle: Arc<Condvar>, terminating: Arc<AtomicBool>, pending_tasks: Arc<AtomicUsize>) -> () {
        let mut consumer_queue = Vec::<Task>::new();

        let finished = || -> bool {
            if !terminating.load(Ordering::Relaxed) {
                return false;
            } else if pending_tasks.load(Ordering::Relaxed) > 0 {
                return false;
            }
            return true;
        };

        // spin until WorkManager has no more tasks
        while !finished() {
            // run all our pending tasks
            for task in &consumer_queue {
                match (*task.closure)() {
                    Ok(_) => {},
                    Err(err) => {
                        panic!("{}", err);
                    }
                }
            }
            // update pending_tasks counter
            pending_tasks.fetch_sub(consumer_queue.len(), Ordering::Relaxed);

            // empty out completed queue
            consumer_queue.clear();

            // finally swap out queues to get new tasks
            let mut producer_queue = producer_queue.lock().unwrap();

            // suspend thread if producer queue is empty and we are not
            // terminating
            if producer_queue.len() == 0 {
                if terminating.load(Ordering::Relaxed) {
                    // suspend for a 16ms rather than busy looping
                    let _ = suspend_handle.wait_timeout(producer_queue, std::time::Duration::from_millis(16)).unwrap();
                } else {
                    let _ = suspend_handle.wait(producer_queue).unwrap();
                }
            } else {
                // otherwise swap the queues and run the tasks
                std::mem::swap::<Vec<Task>>(&mut consumer_queue, &mut producer_queue);
            }
        }
    }
}

#[test]
fn test_work_manager() -> Result<()> {

    let mut work_manager = WorkManager::<3>::new()?;
    let worker_names = ["worker1", "worker2", "worker3"];

    work_manager.start(&worker_names)?;

    work_manager.push(0, || Ok(thread::sleep(std::time::Duration::from_secs(5))))?;

    for i in 0..3 {
        work_manager.push(i as usize, move || Ok(println!("Hello from Worker {}", i)))?;
    }

    match work_manager.push(4, || Ok(())) {
        Ok(result) => {
            bail!("Expected work_manager.push(4,...) to fail");
        },
        _ => ()
    };

    work_manager.join()?;

    return Ok(());
}
