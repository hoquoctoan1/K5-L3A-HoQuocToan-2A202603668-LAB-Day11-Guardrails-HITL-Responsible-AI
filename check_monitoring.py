import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(
    0,
    str(Path(__file__).resolve().parent / "src"),
)

from assignment.monitoring import MonitoringAlert


monitor = MonitoringAlert()

# Chưa có yêu cầu: không chia cho 0, không cảnh báo.
assert monitor.check_metrics() == []

# Tình huống giả lập: 10 yêu cầu, 6 bị chặn do giới hạn.
monitor.total_requests = 10
monitor.blocked_requests = 6
monitor.rate_limit_hits = 6

alerts = monitor.check_metrics()
names = {alert.metric for alert in alerts}

assert names == {"block_rate", "rate_limit_hits"}
assert monitor.snapshot()["block_rate"] == 0.6

# Kiểm tra lại không làm tăng cảnh báo trùng.
assert len(monitor.check_metrics()) == 2

# Đúng ngưỡng: chưa vượt nên không cảnh báo.
monitor.blocked_requests = 5
monitor.rate_limit_hits = 5
assert monitor.check_metrics() == []

# Kiểm tra khả năng xuất số liệu.
with TemporaryDirectory() as folder:
    path = Path(folder) / "metrics.json"
    monitor.export_json(str(path))

    saved = json.loads(path.read_text(encoding="utf-8"))

    assert saved["total_requests"] == 10
    assert saved["block_rate"] == 0.5
    assert saved["alerts"] == []

print("Đạt: tính tỷ lệ, tạo cảnh báo và xuất số liệu đúng.")