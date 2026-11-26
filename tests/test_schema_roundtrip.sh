#!/usr/bin/env bash
set -euo pipefail

SCHEMA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/schema" && pwd)"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo "=== 1. Validating Protobuf syntax and dependencies ==="
protoc -I"$SCHEMA_DIR" --descriptor_set_out="$TMP_DIR/phonelink.desc" "$SCHEMA_DIR"/*.proto
echo "PASS: All .proto files compiled to binary descriptor set."

echo "=== 2. Testing RelayMessage round-trip ==="
cat << 'EOF' > "$TMP_DIR/relay_input.txtpb"
schema_version: 1
type: RELAY_FORWARD
source_device_id: "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
target_device_id: "f0e1d2c3b4a5968778695a4b3c2d1e0ff0e1d2c3b4a5968778695a4b3c2d1e0f"
session_id: "sess_9876543210abcdef"
sequence_number: 42
timestamp: 1774422000000
payload: "EncryptedOpaqueBytesHere"
EOF

protoc -I"$SCHEMA_DIR" --encode=phonelink.relay.RelayMessage "$SCHEMA_DIR/relay.proto" < "$TMP_DIR/relay_input.txtpb" > "$TMP_DIR/relay.bin"
protoc -I"$SCHEMA_DIR" --decode=phonelink.relay.RelayMessage "$SCHEMA_DIR/relay.proto" < "$TMP_DIR/relay.bin" > "$TMP_DIR/relay_output.txtpb"

diff -u "$TMP_DIR/relay_input.txtpb" "$TMP_DIR/relay_output.txtpb"
echo "PASS: RelayMessage round-trip verified."

echo "=== 3. Testing FileListResponse round-trip ==="
cat << 'EOF' > "$TMP_DIR/filelist_input.txtpb"
request_id: "req_fl_100"
current_directory: "Documents"
items {
  path: "Documents/report.pdf"
  name: "report.pdf"
  size_bytes: 1048576
  modified_time: 1774400000000
  mime_type: "application/pdf"
}
items {
  path: "Documents/Projects"
  name: "Projects"
  is_directory: true
  size_bytes: 4096
  modified_time: 1774300000000
  mime_type: "inode/directory"
}
EOF

protoc -I"$SCHEMA_DIR" --encode=phonelink.file.FileListResponse "$SCHEMA_DIR/file.proto" < "$TMP_DIR/filelist_input.txtpb" > "$TMP_DIR/filelist.bin"
protoc -I"$SCHEMA_DIR" --decode=phonelink.file.FileListResponse "$SCHEMA_DIR/file.proto" < "$TMP_DIR/filelist.bin" > "$TMP_DIR/filelist_output.txtpb"

diff -u "$TMP_DIR/filelist_input.txtpb" "$TMP_DIR/filelist_output.txtpb"
echo "PASS: FileListResponse round-trip verified."

echo "=== 4. Testing CameraFrame round-trip ==="
cat << 'EOF' > "$TMP_DIR/camera_input.txtpb"
session_id: "cam_sess_12345"
frame_number: 1
timestamp_ms: 1774422002100
jpeg_data: "\377\330\377\340JFIF"
width: 1280
height: 720
lens: LENS_FRONT
EOF

protoc -I"$SCHEMA_DIR" --encode=phonelink.camera.CameraFrame "$SCHEMA_DIR/camera.proto" < "$TMP_DIR/camera_input.txtpb" > "$TMP_DIR/camera.bin"
protoc -I"$SCHEMA_DIR" --decode=phonelink.camera.CameraFrame "$SCHEMA_DIR/camera.proto" < "$TMP_DIR/camera.bin" > "$TMP_DIR/camera_output.txtpb"

diff -u "$TMP_DIR/camera_input.txtpb" "$TMP_DIR/camera_output.txtpb"
echo "PASS: CameraFrame round-trip verified."

echo "=== 5. Testing ApplicationMessage Union round-trip ==="
cat << 'EOF' > "$TMP_DIR/app_input.txtpb"
schema_version: 1
message_id: "msg_ping_001"
timestamp: 1774422003000
device_ping_req {
  request_id: "ping_req_1"
  duration_seconds: 5
}
EOF

protoc -I"$SCHEMA_DIR" --encode=phonelink.app.ApplicationMessage "$SCHEMA_DIR/app.proto" < "$TMP_DIR/app_input.txtpb" > "$TMP_DIR/app.bin"
protoc -I"$SCHEMA_DIR" --decode=phonelink.app.ApplicationMessage "$SCHEMA_DIR/app.proto" < "$TMP_DIR/app.bin" > "$TMP_DIR/app_output.txtpb"

diff -u "$TMP_DIR/app_input.txtpb" "$TMP_DIR/app_output.txtpb"
echo "PASS: ApplicationMessage round-trip verified."

echo "=== 6. Testing MicAudioChunk & Mic ApplicationMessage round-trip ==="
cat << 'EOF' > "$TMP_DIR/mic_input.txtpb"
session_id: "mic_sess_12345"
chunk_number: 1
timestamp_ms: 1774422004000
pcm_data: "\001\002\003\004"
sample_rate_hz: 16000
channels: 1
bits_per_sample: 16
EOF

protoc -I"$SCHEMA_DIR" --encode=phonelink.mic.MicAudioChunk "$SCHEMA_DIR/mic.proto" < "$TMP_DIR/mic_input.txtpb" > "$TMP_DIR/mic.bin"
protoc -I"$SCHEMA_DIR" --decode=phonelink.mic.MicAudioChunk "$SCHEMA_DIR/mic.proto" < "$TMP_DIR/mic.bin" > "$TMP_DIR/mic_output.txtpb"

diff -u "$TMP_DIR/mic_input.txtpb" "$TMP_DIR/mic_output.txtpb"

cat << 'EOF' > "$TMP_DIR/app_mic_input.txtpb"
schema_version: 1
message_id: "msg_mic_001"
timestamp: 1774422004100
mic_start_req {
  session_id: "mic_sess_12345"
  sample_rate_hz: 16000
  channels: 1
  chunk_duration_ms: 200
}
EOF

protoc -I"$SCHEMA_DIR" --encode=phonelink.app.ApplicationMessage "$SCHEMA_DIR/app.proto" < "$TMP_DIR/app_mic_input.txtpb" > "$TMP_DIR/app_mic.bin"
protoc -I"$SCHEMA_DIR" --decode=phonelink.app.ApplicationMessage "$SCHEMA_DIR/app.proto" < "$TMP_DIR/app_mic.bin" > "$TMP_DIR/app_mic_output.txtpb"

diff -u "$TMP_DIR/app_mic_input.txtpb" "$TMP_DIR/app_mic_output.txtpb"
echo "PASS: MicAudioChunk & ApplicationMessage mic_start_req round-trip verified."

echo ""
echo ">>> ALL ARCH-3 SCHEMA ROUND-TRIP TESTS PASSED! <<<"
