#!/usr/bin/env bash
# Installs the pinned check tools (task, shellcheck, kubeconform, helm) into
# .tools/bin for task k8s:check on a linux amd64 CI runner.
set -euo pipefail
LAB_STEP=k8s:check-tools
# shellcheck source=../lib.sh
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"

LAB_ARCH=amd64
ensure_tool task "https://github.com/go-task/task/releases/download/$TASK_VERSION/task_linux_amd64.tar.gz" \
  "$(pinned TASK_SHA256)" task
ensure_tool shellcheck "https://github.com/koalaman/shellcheck/releases/download/$SHELLCHECK_VERSION/shellcheck-$SHELLCHECK_VERSION.linux.x86_64.tar.xz" \
  "$(pinned SHELLCHECK_SHA256)" "shellcheck-$SHELLCHECK_VERSION/shellcheck"
ensure_tool kubeconform "https://github.com/yannh/kubeconform/releases/download/$KUBECONFORM_VERSION/kubeconform-linux-amd64.tar.gz" \
  "$(pinned KUBECONFORM_SHA256)" kubeconform
ensure_tool helm "https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz" "$(pinned HELM_SHA256)" linux-amd64/helm
echo "$LAB_TOOLS_DIR/bin"
