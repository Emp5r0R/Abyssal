use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoomPolicy {
    #[serde(with = "crate::mls_wire::decimal_u64")]
    pub self_destruct_timer_sec: u64,
    #[serde(with = "crate::mls_wire::decimal_u64")]
    pub overall_expiry_sec: u64,
    pub allow_images: bool,
    pub allow_videos: bool,
    pub allow_files: bool,
    pub enforce_text_absolute_expiry: bool,
    #[serde(with = "crate::mls_wire::decimal_u64")]
    pub image_read_timer_sec: u64,
    #[serde(with = "crate::mls_wire::decimal_u64")]
    pub image_overall_expiry_sec: u64,
    pub enforce_image_absolute_expiry: bool,
    #[serde(with = "crate::mls_wire::decimal_u64")]
    pub video_read_timer_sec: u64,
    #[serde(with = "crate::mls_wire::decimal_u64")]
    pub video_overall_expiry_sec: u64,
    pub enforce_video_absolute_expiry: bool,
    #[serde(with = "crate::mls_wire::decimal_u64")]
    pub file_read_timer_sec: u64,
    #[serde(with = "crate::mls_wire::decimal_u64")]
    pub file_overall_expiry_sec: u64,
    pub enforce_file_absolute_expiry: bool,
}

impl Default for RoomPolicy {
    fn default() -> Self {
        Self {
            self_destruct_timer_sec: 0,
            overall_expiry_sec: 0,
            allow_images: true,
            allow_videos: true,
            allow_files: true,
            enforce_text_absolute_expiry: false,
            image_read_timer_sec: 0,
            image_overall_expiry_sec: 0,
            enforce_image_absolute_expiry: false,
            video_read_timer_sec: 0,
            video_overall_expiry_sec: 0,
            enforce_video_absolute_expiry: false,
            file_read_timer_sec: 0,
            file_overall_expiry_sec: 0,
            enforce_file_absolute_expiry: false,
        }
    }
}

impl RoomPolicy {
    pub(super) fn normalized(mut self) -> Self {
        self.self_destruct_timer_sec = self.self_destruct_timer_sec.min(86_400);
        self.overall_expiry_sec = self.overall_expiry_sec.min(86_400);
        self.image_read_timer_sec = self.image_read_timer_sec.min(86_400);
        self.image_overall_expiry_sec = self.image_overall_expiry_sec.min(86_400);
        self.video_read_timer_sec = self.video_read_timer_sec.min(86_400);
        self.video_overall_expiry_sec = self.video_overall_expiry_sec.min(86_400);
        self.file_read_timer_sec = self.file_read_timer_sec.min(86_400);
        self.file_overall_expiry_sec = self.file_overall_expiry_sec.min(86_400);
        self
    }
}
