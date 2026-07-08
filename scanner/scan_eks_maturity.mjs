#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import yaml from "js-yaml";

const WORKLOAD_KINDS = new Set(["Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod"]);
const SECRET_NAME_PATTERN = /(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)/i;
const SYSTEM_NAMESPACES = new Set(["kube-system", "kube-public", "kube-node-lease"]);
const ITEM_METADATA = {
  "quick-wins/non-root-containers": { phase: "Quick Wins", domain: "Pod 보안" },
  "quick-wins/default-service-account": { phase: "Quick Wins", domain: "접근 제어" },
  "quick-wins/ingress-load-balancer-tls": { phase: "Quick Wins", domain: "네트워크 보안" },
  "quick-wins/resource-quota-limitrange": { phase: "Quick Wins", domain: "Pod 보안" },
  "quick-wins/aws-secret-manager-사용": { phase: "Quick Wins", domain: "데이터 보호" },
  "foundational/private-api-endpoint": { phase: "Foundational", domain: "네트워크 보안" },
  "foundational/private-subnets": { phase: "Foundational", domain: "네트워크 보안" },
  "efficient/default-deny-networkpolicy": { phase: "Efficient", domain: "네트워크 보안" },
  "foundational/pod-실행-권한-최소화": { phase: "Foundational", domain: "Pod 보안" },
  "foundational/iam-k8s-mapping": { phase: "Foundational", domain: "접근 제어" },
  "foundational/container-image-취약점-관리": { phase: "Foundational", domain: "Pod 보안" },
  "foundational/grafana-대시보드-연결": { phase: "Foundational", domain: "Pod 보안" },
  "foundational/ebs-기반-workload-storage-data-보호": { phase: "Foundational", domain: "데이터 보호" },
  "foundational/workload-내-hardcoded-secret-제거": { phase: "Foundational", domain: "데이터 보호" },
  "foundational/cluster내-리소스-접근제어": { phase: "Foundational", domain: "접근 제어" },
};
const PRIORITY_ORDER = new Map([
  ["P1", 0],
  ["P2", 1],
  ["P3", 2],
]);
const STATUS_ORDER = new Map([
  ["fail", 0],
  ["warn", 1],
  ["unknown", 2],
  ["pass", 3],
]);

function listYamlFiles(dir) {
  if (!existsSync(dir)) return [];

  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    if (entry.name === "node_modules" || entry.name === ".git" || entry.name === "dist") return [];
    const current = path.join(dir, entry.name);
    if (entry.isDirectory()) return listYamlFiles(current);
    return /\.(ya?ml)$/.test(entry.name) ? [current] : [];
  });
}

function loadDocuments(repoRoot) {
  return listYamlFiles(repoRoot).flatMap((file) => {
    const relative = path.relative(repoRoot, file);
    try {
      return yaml.loadAll(readFileSync(file, "utf8"))
        .filter((doc) => doc && typeof doc === "object")
        .map((doc) => ({ file: relative, doc }));
    } catch (error) {
      return [{ file: relative, doc: { kind: "__ParseError", message: error.message } }];
    }
  });
}

function namespaceOf(doc) {
  return doc?.metadata?.namespace || "default";
}

function podSpecFor(doc) {
  if (!WORKLOAD_KINDS.has(doc.kind)) return null;
  if (doc.kind === "Pod") return doc.spec ?? null;
  if (doc.kind === "CronJob") return doc.spec?.jobTemplate?.spec?.template?.spec ?? null;
  return doc.spec?.template?.spec ?? null;
}

function containersFor(podSpec) {
  return [...(podSpec?.containers ?? []), ...(podSpec?.initContainers ?? [])];
}

function priorityFor(status, severity) {
  if (status === "fail" && severity === "high") return "P1";
  if (status === "fail" && severity === "medium") return "P2";
  if (status === "warn" && (severity === "high" || severity === "medium")) return "P2";
  return "P3";
}

function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const priority = (PRIORITY_ORDER.get(a.priority) ?? 99) - (PRIORITY_ORDER.get(b.priority) ?? 99);
    if (priority !== 0) return priority;

    const status = (STATUS_ORDER.get(a.status) ?? 99) - (STATUS_ORDER.get(b.status) ?? 99);
    if (status !== 0) return status;

    return a.item_id.localeCompare(b.item_id);
  });
}

function finding(item_id, status, severity, evidence, recommendation, verify_commands = []) {
  const metadata = ITEM_METADATA[item_id] ?? { phase: "Unknown", domain: "미분류" };
  return {
    item_id,
    phase: metadata.phase,
    domain: metadata.domain,
    status,
    severity,
    priority: priorityFor(status, severity),
    evidence,
    recommendation,
    verify_commands,
    source_reference: `references/catalog.json#${item_id}`,
  };
}

function checkNonRoot(entries) {
  const workloads = entries
    .map(({ file, doc }) => ({ file, doc, podSpec: podSpecFor(doc) }))
    .filter((entry) => entry.podSpec);

  if (workloads.length === 0) {
    return finding(
      "quick-wins/non-root-containers",
      "unknown",
      "medium",
      ["Kubernetes 워크로드 매니페스트를 찾지 못했습니다."],
      "정적 non-root 진단을 위해 Deployment, StatefulSet, DaemonSet, Job, CronJob 또는 Pod 매니페스트를 추가하세요.",
    );
  }

  const failures = [];
  for (const { file, doc, podSpec } of workloads) {
    const podContext = podSpec.securityContext ?? {};
    for (const container of containersFor(podSpec)) {
      const context = container.securityContext ?? {};
      const runAsUser = context.runAsUser ?? podContext.runAsUser;
      const runAsNonRoot = context.runAsNonRoot ?? podContext.runAsNonRoot;

      if (runAsUser === 0 || runAsNonRoot !== true) {
        failures.push(`${file}: ${doc.kind}/${doc.metadata?.name ?? "<unnamed>"}의 컨테이너 ${container.name ?? "<unnamed>"}가 runAsNonRoot=true를 설정하지 않았거나 UID 0으로 실행됩니다.`);
      }
    }
  }

  return finding(
    "quick-wins/non-root-containers",
    failures.length > 0 ? "fail" : "pass",
    failures.length > 0 ? "high" : "low",
    failures.length > 0 ? failures : [`${workloads.length}개 워크로드 매니페스트가 non-root 실행을 선언합니다.`],
    "Pod 또는 컨테이너 securityContext에 runAsNonRoot=true와 0이 아닌 runAsUser를 설정하고, 가능하면 readOnlyRootFilesystem 같은 컨테이너 강화 설정을 추가하세요.",
    ["kubectl get deploy,statefulset,daemonset -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{\"\\t\"}{.spec.template.spec.securityContext}{\"\\n\"}{end}'"],
  );
}

function checkServiceAccounts(entries) {
  const workloads = entries
    .map(({ file, doc }) => ({ file, doc, podSpec: podSpecFor(doc) }))
    .filter((entry) => entry.podSpec);

  if (workloads.length === 0) {
    return finding("quick-wins/default-service-account", "unknown", "medium", ["Kubernetes 워크로드 매니페스트를 찾지 못했습니다."], "ServiceAccount 사용 여부를 평가하려면 먼저 워크로드 매니페스트를 추가하세요.");
  }

  const failures = [];
  for (const { file, doc, podSpec } of workloads) {
    const serviceAccountName = podSpec.serviceAccountName ?? "default";
    const automount = podSpec.automountServiceAccountToken;
    if (serviceAccountName === "default" || automount !== false) {
      failures.push(`${file}: ${doc.kind}/${doc.metadata?.name ?? "<unnamed>"}가 ServiceAccount ${serviceAccountName}를 사용하며 automountServiceAccountToken=${String(automount)}입니다.`);
    }
  }

  return finding(
    "quick-wins/default-service-account",
    failures.length > 0 ? "fail" : "pass",
    failures.length > 0 ? "high" : "low",
    failures.length > 0 ? failures : [`${workloads.length}개 워크로드 매니페스트가 default ServiceAccount 토큰 자동 마운트를 피하고 있습니다.`],
    "워크로드별 ServiceAccount를 사용하고, Kubernetes API 접근이 필요한 경우가 아니라면 automountServiceAccountToken=false를 설정하세요.",
    ["kubectl get deploy,statefulset,daemonset -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{\"\\t\"}{.spec.template.spec.serviceAccountName}{\"\\t\"}{.spec.template.spec.automountServiceAccountToken}{\"\\n\"}{end}'"],
  );
}

function ingressHasTls(doc) {
  const annotations = doc.metadata?.annotations ?? {};
  const listenPorts = annotations["alb.ingress.kubernetes.io/listen-ports"] ?? "";
  const hasAlbTls = Boolean(annotations["alb.ingress.kubernetes.io/certificate-arn"]) && /HTTPS/.test(listenPorts);
  return (doc.spec?.tls ?? []).length > 0 || hasAlbTls;
}

function checkIngressTls(entries) {
  const ingresses = entries.filter(({ doc }) => doc.kind === "Ingress");
  if (ingresses.length === 0) {
    return finding("quick-wins/ingress-load-balancer-tls", "unknown", "medium", ["Ingress 매니페스트를 찾지 못했습니다."], "Ingress 또는 Load Balancer 매니페스트가 생긴 뒤 TLS 설정을 평가하세요.");
  }

  const failures = ingresses
    .filter(({ doc }) => !ingressHasTls(doc))
    .map(({ file, doc }) => `${file}: Ingress/${doc.metadata?.name ?? "<unnamed>"}에 spec.tls 또는 ALB HTTPS 인증서 annotation이 없습니다.`);

  return finding(
    "quick-wins/ingress-load-balancer-tls",
    failures.length > 0 ? "fail" : "pass",
    failures.length > 0 ? "high" : "low",
    failures.length > 0 ? failures : [`${ingresses.length}개 Ingress 매니페스트가 TLS termination을 선언합니다.`],
    "Kubernetes Ingress에는 spec.tls를 선언하고, AWS Load Balancer Controller를 쓰는 경우 HTTPS listener, ACM certificate ARN, SSL redirect annotation을 설정하세요.",
    ["kubectl get ingress -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{\"\\t\"}{.spec.tls}{\"\\t\"}{.metadata.annotations}{\"\\n\"}{end}'"],
  );
}

function checkQuotaAndLimits(entries) {
  const workloadNamespaces = new Set(
    entries
      .filter(({ doc }) => podSpecFor(doc))
      .map(({ doc }) => namespaceOf(doc)),
  );
  const quotaNamespaces = new Set(entries.filter(({ doc }) => doc.kind === "ResourceQuota").map(({ doc }) => namespaceOf(doc)));
  const limitNamespaces = new Set(entries.filter(({ doc }) => doc.kind === "LimitRange").map(({ doc }) => namespaceOf(doc)));

  if (workloadNamespaces.size === 0) {
    return finding("quick-wins/resource-quota-limitrange", "unknown", "medium", ["워크로드 네임스페이스를 찾지 못했습니다."], "네임스페이스 quota와 기본 limit을 평가하려면 먼저 워크로드 매니페스트를 추가하세요.");
  }

  const failures = [...workloadNamespaces].flatMap((namespace) => {
    const missing = [];
    if (!quotaNamespaces.has(namespace)) missing.push("ResourceQuota");
    if (!limitNamespaces.has(namespace)) missing.push("LimitRange");
    return missing.length > 0 ? [`네임스페이스 ${namespace}에 ${missing.join(" 및 ")}가 없습니다.`] : [];
  });

  return finding(
    "quick-wins/resource-quota-limitrange",
    failures.length > 0 ? "fail" : "pass",
    failures.length > 0 ? "medium" : "low",
    failures.length > 0 ? failures : [`${workloadNamespaces.size}개 네임스페이스에 ResourceQuota와 LimitRange가 있습니다.`],
    "모든 애플리케이션 네임스페이스에 ResourceQuota와 LimitRange를 정의해 워크로드 request/limit이 경계 안에서 관리되도록 하세요.",
    ["kubectl get resourcequota,limitrange -A"],
  );
}

function hasHardcodedSecret(obj) {
  if (Array.isArray(obj)) return obj.some(hasHardcodedSecret);
  if (!obj || typeof obj !== "object") return false;

  if (typeof obj.name === "string" && Object.hasOwn(obj, "value") && typeof obj.value === "string") {
    return SECRET_NAME_PATTERN.test(obj.name) && obj.value.length > 0;
  }

  return Object.values(obj).some(hasHardcodedSecret);
}

function checkHardcodedSecrets(entries) {
  const failures = entries
    .filter(({ doc }) => hasHardcodedSecret(doc))
    .map(({ file, doc }) => `${file}: ${doc.kind ?? "Document"}/${doc.metadata?.name ?? "<unnamed>"}에 env 형식의 Secret literal 값이 포함되어 있습니다.`);

  return finding(
    "quick-wins/aws-secret-manager-사용",
    failures.length > 0 ? "fail" : "pass",
    failures.length > 0 ? "high" : "low",
    failures.length > 0 ? failures : ["Secret처럼 보이는 이름의 env[].value literal 항목을 찾지 못했습니다."],
    "literal Secret 값은 AWS Secrets Manager 또는 승인된 외부 Secret 저장소로 옮기고, ESO, CSI, 애플리케이션 런타임 조회 방식으로 참조하세요.",
    ["kubectl get deploy,statefulset,daemonset -A -o yaml | grep -Ei 'password|secret|token|api[_-]?key'"],
  );
}

function defaultCommandRunner({ command, args }) {
  return execFileSync(command, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

function readJson(commandRunner, command, args) {
  try {
    const output = commandRunner({ command, args });
    return { ok: true, data: JSON.parse(output || "{}") };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

function readText(commandRunner, command, args) {
  try {
    return { ok: true, text: commandRunner({ command, args }) };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

function awsArgs(service, operation, args, { region, profile } = {}) {
  return [
    service,
    operation,
    ...args,
    ...(region ? ["--region", region] : []),
    ...(profile ? ["--profile", profile] : []),
    "--output",
    "json",
  ];
}

function kubectlArgs(args, { context } = {}) {
  return [...args, ...(context ? ["--context", context] : [])];
}

function missingLiveConfig(itemId, missing, verifyCommands) {
  return finding(
    itemId,
    "unknown",
    "medium",
    [`live scan 입력값이 부족합니다: ${missing.join(", ")}.`],
    "부족한 live scan 입력값을 제공한 뒤 read-only scanner를 다시 실행하세요.",
    verifyCommands,
  );
}

function commandUnknown(itemId, error, recommendation, verifyCommands) {
  return finding(itemId, "unknown", "medium", [`read-only 명령 실행에 실패했습니다: ${error}`], recommendation, verifyCommands);
}

function applicationNamespacesFromPods(pods) {
  return new Set(
    (pods.items ?? [])
      .map((pod) => pod.metadata?.namespace ?? "default")
      .filter((namespace) => !SYSTEM_NAMESPACES.has(namespace)),
  );
}

function isEmptySelector(selector) {
  return selector && typeof selector === "object" && Object.keys(selector).length === 0;
}

function liveContainersForPod(pod) {
  return [...(pod.spec?.containers ?? []), ...(pod.spec?.initContainers ?? [])];
}

function workloadPodSpecForLive(item) {
  if (item.kind === "Pod") return item.spec ?? null;
  if (item.kind === "CronJob") return item.spec?.jobTemplate?.spec?.template?.spec ?? null;
  return item.spec?.template?.spec ?? null;
}

function parseEksContextArn(context) {
  const match = /^arn:aws[^:]*:eks:([^:]+):\d+:cluster\/(.+)$/.exec(context ?? "");
  if (!match) return {};
  return { region: match[1], clusterName: match[2] };
}

function valueAfter(args, flag) {
  const index = args.indexOf(flag);
  return index === -1 ? null : args[index + 1];
}

export function detectLiveConfig({ commandRunner = defaultCommandRunner } = {}) {
  const current = readText(commandRunner, "kubectl", ["config", "current-context"]);
  if (!current.ok) return {};

  const context = current.text.trim();
  const fromContext = parseEksContextArn(context);
  const config = readJson(commandRunner, "kubectl", ["config", "view", "--minify", "-o", "json"]);
  const execConfig = config.ok ? config.data.users?.[0]?.user?.exec ?? {} : {};
  const execArgs = execConfig.args ?? [];
  const profile = (execConfig.env ?? []).find((entry) => entry.name === "AWS_PROFILE")?.value ?? null;

  return {
    context,
    clusterName: valueAfter(execArgs, "--cluster-name") ?? fromContext.clusterName ?? null,
    region: valueAfter(execArgs, "--region") ?? fromContext.region ?? null,
    profile,
  };
}

function checkLivePrivateApiEndpoint(options) {
  const verifyCommands = [
    "aws eks describe-cluster --name <cluster-name> --region <region> --query 'cluster.resourcesVpcConfig.{endpointPublicAccess:endpointPublicAccess,endpointPrivateAccess:endpointPrivateAccess}' --output json",
  ];
  const missing = [];
  if (!options.clusterName) missing.push("clusterName");
  if (!options.region) missing.push("region");
  if (missing.length > 0) return missingLiveConfig("foundational/private-api-endpoint", missing, verifyCommands);

  const result = readJson(
    options.commandRunner,
    "aws",
    awsArgs("eks", "describe-cluster", ["--name", options.clusterName], options),
  );
  if (!result.ok) {
    return commandUnknown("foundational/private-api-endpoint", result.error, "read-only AWS 자격 증명으로 EKS cluster endpoint 조회를 실행하세요.", verifyCommands);
  }

  const config = result.data.cluster?.resourcesVpcConfig ?? {};
  const passes = config.endpointPublicAccess === false && config.endpointPrivateAccess === true;
  return finding(
    "foundational/private-api-endpoint",
    passes ? "pass" : "fail",
    passes ? "low" : "high",
    [`endpointPublicAccess=${String(config.endpointPublicAccess)}, endpointPrivateAccess=${String(config.endpointPrivateAccess)}`],
    "운영 클러스터는 private-only EKS API endpoint를 사용하고, 승인된 private 네트워크 경로를 통해서만 접근하도록 구성하세요.",
    verifyCommands,
  );
}

function checkLivePrivateSubnets(options) {
  const verifyCommands = [
    "aws eks list-nodegroups --cluster-name <cluster-name> --region <region> --output json",
    "aws eks describe-nodegroup --cluster-name <cluster-name> --nodegroup-name <nodegroup> --region <region> --query 'nodegroup.subnets' --output json",
    "aws ec2 describe-subnets --subnet-ids <subnet-ids> --region <region> --query 'Subnets[].{SubnetId:SubnetId,MapPublicIpOnLaunch:MapPublicIpOnLaunch}' --output json",
  ];
  const missing = [];
  if (!options.clusterName) missing.push("clusterName");
  if (!options.region) missing.push("region");
  if (missing.length > 0) return missingLiveConfig("foundational/private-subnets", missing, verifyCommands);

  const nodegroups = readJson(
    options.commandRunner,
    "aws",
    awsArgs("eks", "list-nodegroups", ["--cluster-name", options.clusterName], options),
  );
  if (!nodegroups.ok) {
    return commandUnknown("foundational/private-subnets", nodegroups.error, "read-only AWS 자격 증명으로 EKS managed nodegroup 목록을 조회하세요.", verifyCommands);
  }

  const subnetIds = new Set();
  for (const nodegroupName of nodegroups.data.nodegroups ?? []) {
    const nodegroup = readJson(
      options.commandRunner,
      "aws",
      awsArgs("eks", "describe-nodegroup", ["--cluster-name", options.clusterName, "--nodegroup-name", nodegroupName], options),
    );
    if (!nodegroup.ok) {
      return commandUnknown("foundational/private-subnets", nodegroup.error, `read-only AWS 자격 증명으로 nodegroup ${nodegroupName} 상세 정보를 조회하세요.`, verifyCommands);
    }
    for (const subnetId of nodegroup.data.nodegroup?.subnets ?? []) subnetIds.add(subnetId);
  }

  if (subnetIds.size === 0) {
    return finding("foundational/private-subnets", "unknown", "medium", ["EKS managed nodegroup subnet 정보가 반환되지 않았습니다."], "self-managed nodegroup, Fargate profile 또는 Terraform output에서 node 배치 정보를 확인하세요.", verifyCommands);
  }

  const subnets = readJson(
    options.commandRunner,
    "aws",
    awsArgs("ec2", "describe-subnets", ["--subnet-ids", ...subnetIds], options),
  );
  if (!subnets.ok) {
    return commandUnknown("foundational/private-subnets", subnets.error, "read-only EC2 권한으로 nodegroup subnet 상세 정보를 조회하세요.", verifyCommands);
  }

  const publicSubnets = (subnets.data.Subnets ?? []).filter((subnet) => subnet.MapPublicIpOnLaunch === true);
  return finding(
    "foundational/private-subnets",
    publicSubnets.length > 0 ? "fail" : "pass",
    publicSubnets.length > 0 ? "high" : "low",
    publicSubnets.length > 0
      ? publicSubnets.map((subnet) => `${subnet.SubnetId}가 인스턴스 시작 시 public IP를 자동 할당합니다.`)
      : [`${subnetIds.size}개 nodegroup subnet이 인스턴스 시작 시 public IP를 자동 할당하지 않습니다.`],
    "Worker node와 Pod 네트워킹은 private subnet에 배치하고, public subnet 배치 대신 통제된 egress 경로를 사용하세요.",
    verifyCommands,
  );
}

function checkLiveDefaultDenyNetworkPolicy(options) {
  const verifyCommands = ["kubectl get pods -A -o json", "kubectl get networkpolicy -A -o json"];
  if (!options.context) return missingLiveConfig("efficient/default-deny-networkpolicy", ["context"], verifyCommands);

  const pods = readJson(options.commandRunner, "kubectl", kubectlArgs(["get", "pods", "-A", "-o", "json"], options));
  if (!pods.ok) {
    return commandUnknown("efficient/default-deny-networkpolicy", pods.error, "선택한 context로 kubectl을 사용해 Pod 목록을 조회하세요.", verifyCommands);
  }

  const workloadNamespaces = applicationNamespacesFromPods(pods.data);
  if (workloadNamespaces.size === 0) {
    return finding("efficient/default-deny-networkpolicy", "unknown", "medium", ["애플리케이션 워크로드 네임스페이스를 찾지 못했습니다."], "워크로드가 생성된 뒤 다시 점검하거나 네임스페이스 범위를 명시적으로 제공하세요.", verifyCommands);
  }

  const policies = readJson(options.commandRunner, "kubectl", kubectlArgs(["get", "networkpolicy", "-A", "-o", "json"], options));
  if (!policies.ok) {
    return commandUnknown("efficient/default-deny-networkpolicy", policies.error, "선택한 context로 kubectl을 사용해 NetworkPolicy 객체를 조회하세요.", verifyCommands);
  }

  const protectedNamespaces = new Set(
    (policies.data.items ?? [])
      .filter((policy) => isEmptySelector(policy.spec?.podSelector) && (policy.spec?.policyTypes ?? []).some((type) => type === "Ingress" || type === "Egress"))
      .map((policy) => policy.metadata?.namespace ?? "default"),
  );
  const missing = [...workloadNamespaces].filter((namespace) => !protectedNamespaces.has(namespace));

  return finding(
    "efficient/default-deny-networkpolicy",
    missing.length > 0 ? "fail" : "pass",
    missing.length > 0 ? "high" : "low",
    missing.length > 0 ? missing.map((namespace) => `네임스페이스 ${namespace}에 default deny NetworkPolicy가 없습니다.`) : [`${workloadNamespaces.size}개 워크로드 네임스페이스에 default deny NetworkPolicy가 적용되어 있습니다.`],
    "명시적인 워크로드 허용 정책을 추가하기 전에 네임스페이스 수준 default deny NetworkPolicy를 적용하세요.",
    verifyCommands,
  );
}

function checkLivePodSecurityBaseline(options) {
  const verifyCommands = [
    "kubectl get namespaces -o json",
    "kubectl get pods -A -o json",
  ];
  if (!options.context) return missingLiveConfig("foundational/pod-실행-권한-최소화", ["context"], verifyCommands);

  const namespaces = readJson(options.commandRunner, "kubectl", kubectlArgs(["get", "namespaces", "-o", "json"], options));
  if (!namespaces.ok) {
    return commandUnknown("foundational/pod-실행-권한-최소화", namespaces.error, "선택한 context로 kubectl을 사용해 namespace label을 조회하세요.", verifyCommands);
  }

  const pods = readJson(options.commandRunner, "kubectl", kubectlArgs(["get", "pods", "-A", "-o", "json"], options));
  if (!pods.ok) {
    return commandUnknown("foundational/pod-실행-권한-최소화", pods.error, "선택한 context로 kubectl을 사용해 Pod spec을 조회하세요.", verifyCommands);
  }

  const workloadNamespaces = applicationNamespacesFromPods(pods.data);
  if (workloadNamespaces.size === 0) {
    return finding("foundational/pod-실행-권한-최소화", "unknown", "medium", ["애플리케이션 워크로드 네임스페이스를 찾지 못했습니다."], "워크로드가 생성된 뒤 다시 점검하거나 네임스페이스 범위를 명시적으로 제공하세요.", verifyCommands);
  }

  const labelsByNamespace = new Map((namespaces.data.items ?? []).map((namespace) => [namespace.metadata?.name, namespace.metadata?.labels ?? {}]));
  const failures = [];
  for (const namespace of workloadNamespaces) {
    const enforce = labelsByNamespace.get(namespace)?.["pod-security.kubernetes.io/enforce"];
    if (enforce !== "baseline" && enforce !== "restricted") {
      failures.push(`네임스페이스 ${namespace}가 PSS baseline 또는 restricted를 enforce하지 않습니다.`);
    }
  }

  for (const pod of pods.data.items ?? []) {
    const namespace = pod.metadata?.namespace ?? "default";
    if (!workloadNamespaces.has(namespace)) continue;
    for (const container of liveContainersForPod(pod)) {
      if (container.securityContext?.privileged === true) {
        failures.push(`${namespace}/${pod.metadata?.name ?? "<unnamed>"}의 컨테이너 ${container.name ?? "<unnamed>"}가 privileged로 실행됩니다.`);
      }
    }
  }

  return finding(
    "foundational/pod-실행-권한-최소화",
    failures.length > 0 ? "fail" : "pass",
    failures.length > 0 ? "high" : "low",
    failures.length > 0 ? failures : [`${workloadNamespaces.size}개 워크로드 네임스페이스가 PSS baseline/restricted를 enforce하며 privileged 컨테이너가 관측되지 않았습니다.`],
    "Pod Security Standards를 최소 baseline 이상으로 enforce하고 애플리케이션 네임스페이스에서 privileged 컨테이너 실행을 제거하세요.",
    verifyCommands,
  );
}

function checkLiveIamK8sMapping(options) {
  const verifyCommands = [
    "aws eks describe-cluster --name <cluster-name> --region <region> --query 'cluster.accessConfig' --output json",
    "aws eks list-access-entries --cluster-name <cluster-name> --region <region> --output json",
  ];
  const missing = [];
  if (!options.clusterName) missing.push("clusterName");
  if (!options.region) missing.push("region");
  if (missing.length > 0) return missingLiveConfig("foundational/iam-k8s-mapping", missing, verifyCommands);

  const cluster = readJson(
    options.commandRunner,
    "aws",
    awsArgs("eks", "describe-cluster", ["--name", options.clusterName], options),
  );
  if (!cluster.ok) {
    return commandUnknown("foundational/iam-k8s-mapping", cluster.error, "read-only AWS 자격 증명으로 EKS access configuration을 조회하세요.", verifyCommands);
  }

  const entries = readJson(
    options.commandRunner,
    "aws",
    awsArgs("eks", "list-access-entries", ["--cluster-name", options.clusterName], options),
  );
  if (!entries.ok) {
    return commandUnknown("foundational/iam-k8s-mapping", entries.error, "read-only AWS 자격 증명으로 EKS access entry 목록을 조회하세요.", verifyCommands);
  }

  const authenticationMode = cluster.data.cluster?.accessConfig?.authenticationMode ?? "unknown";
  const accessEntries = entries.data.accessEntries ?? [];
  const usesApi = authenticationMode.includes("API");
  const passes = usesApi && accessEntries.length > 0;
  const status = passes ? "pass" : usesApi ? "warn" : "fail";

  return finding(
    "foundational/iam-k8s-mapping",
    status,
    passes ? "low" : usesApi ? "medium" : "high",
    [`authenticationMode=${authenticationMode}, accessEntries=${accessEntries.length}`],
    "클러스터 접근은 EKS Access Entries로 관리하고 IAM-to-Kubernetes 접근 매핑을 명시적이고 리뷰 가능한 상태로 유지하세요.",
    verifyCommands,
  );
}

function checkLiveContainerImageTriage(options) {
  const verifyCommands = [
    "aws inspector2 list-filters --action SUPPRESS --region <region> --output json",
    "aws inspector2 list-findings --region <region> --filter-criteria '<critical-high-ecr-active-filter>' --output json",
  ];
  if (!options.region) return missingLiveConfig("foundational/container-image-취약점-관리", ["region"], verifyCommands);

  const filters = readJson(options.commandRunner, "aws", awsArgs("inspector2", "list-filters", ["--action", "SUPPRESS"], options));
  if (!filters.ok) {
    return commandUnknown("foundational/container-image-취약점-관리", filters.error, "read-only AWS 자격 증명으로 Inspector suppression filter 목록을 조회하세요.", verifyCommands);
  }

  const findings = readJson(
    options.commandRunner,
    "aws",
    awsArgs("inspector2", "list-findings", [
      "--filter-criteria",
      '{"resourceType":[{"comparison":"EQUALS","value":"AWS_ECR_CONTAINER_IMAGE"}],"findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"}],"severity":[{"comparison":"EQUALS","value":"CRITICAL"},{"comparison":"EQUALS","value":"HIGH"}]}',
    ], options),
  );
  if (!findings.ok) {
    return commandUnknown("foundational/container-image-취약점-관리", findings.error, "read-only AWS 자격 증명으로 활성 Critical/High ECR Inspector finding을 조회하세요.", verifyCommands);
  }

  const suppressFilters = filters.data.filters ?? [];
  const activeFindings = findings.data.findings ?? [];
  const status = activeFindings.length > 0 ? "fail" : suppressFilters.length > 0 ? "pass" : "warn";
  return finding(
    "foundational/container-image-취약점-관리",
    status,
    activeFindings.length > 0 ? "high" : status === "warn" ? "medium" : "low",
    [
      `${suppressFilters.length}개 Inspector suppression filter를 찾았습니다.`,
      `${activeFindings.length}개 활성 Critical/High ECR finding을 찾았습니다.`,
    ],
    "문서화된 Inspector triage suppression filter를 유지하고 활성 Critical/High ECR finding은 합의된 SLA 안에 조치하세요.",
    verifyCommands,
  );
}

function checkLiveGrafana(options) {
  const verifyCommands = [
    "kubectl get pods -n monitoring -l app.kubernetes.io/name=grafana -o json",
    "kubectl get pvc -n monitoring -o json",
    "kubectl get ingress -n monitoring -o json",
  ];
  if (!options.context) return missingLiveConfig("foundational/grafana-대시보드-연결", ["context"], verifyCommands);

  const pods = readJson(options.commandRunner, "kubectl", kubectlArgs(["get", "pods", "-n", "monitoring", "-l", "app.kubernetes.io/name=grafana", "-o", "json"], options));
  if (!pods.ok) return commandUnknown("foundational/grafana-대시보드-연결", pods.error, "monitoring 네임스페이스의 Grafana Pod를 조회하세요.", verifyCommands);

  const pvcs = readJson(options.commandRunner, "kubectl", kubectlArgs(["get", "pvc", "-n", "monitoring", "-o", "json"], options));
  if (!pvcs.ok) return commandUnknown("foundational/grafana-대시보드-연결", pvcs.error, "monitoring 네임스페이스의 Grafana PVC를 조회하세요.", verifyCommands);

  const ingresses = readJson(options.commandRunner, "kubectl", kubectlArgs(["get", "ingress", "-n", "monitoring", "-o", "json"], options));
  if (!ingresses.ok) return commandUnknown("foundational/grafana-대시보드-연결", ingresses.error, "monitoring 네임스페이스의 Grafana Ingress를 조회하세요.", verifyCommands);

  const runningPods = (pods.data.items ?? []).filter((pod) => pod.status?.phase === "Running");
  const grafanaPvcs = (pvcs.data.items ?? []).filter((pvc) => /grafana/i.test(pvc.metadata?.name ?? ""));
  const boundPvcs = grafanaPvcs.filter((pvc) => pvc.status?.phase === "Bound");
  const hasIngress = (ingresses.data.items ?? []).length > 0;
  const failures = [];
  if (runningPods.length === 0) failures.push("monitoring 네임스페이스에서 Running 상태의 Grafana Pod를 찾지 못했습니다.");
  if (grafanaPvcs.length > 0 && boundPvcs.length !== grafanaPvcs.length) failures.push("Grafana PVC 중 하나 이상이 Bound 상태가 아닙니다.");
  if (!hasIngress) failures.push("monitoring 네임스페이스에서 Grafana Ingress를 찾지 못했습니다.");

  return finding(
    "foundational/grafana-대시보드-연결",
    failures.length > 0 ? "warn" : "pass",
    failures.length > 0 ? "medium" : "low",
    failures.length > 0 ? failures : [`${runningPods.length}개 Grafana Pod가 Running이고, ${boundPvcs.length}개 Grafana PVC가 Bound이며, Ingress가 존재합니다.`],
    "Grafana를 지속적인 암호화 스토리지와 명시적으로 검토된 접근 경로로 운영하세요.",
    verifyCommands,
  );
}

function volumeIdFromHandle(handle) {
  if (!handle) return null;
  const match = /(vol-[a-zA-Z0-9]+)/.exec(handle);
  return match?.[1] ?? null;
}

function checkLiveEbsStorageProtection(options) {
  const verifyCommands = [
    "aws ec2 get-ebs-encryption-by-default --region <region> --output json",
    "kubectl get storageclass -o json",
    "kubectl get pvc -A -o json",
    "kubectl get pv -o json",
  ];
  const missing = [];
  if (!options.region) missing.push("region");
  if (!options.context) missing.push("context");
  if (missing.length > 0) return missingLiveConfig("foundational/ebs-기반-workload-storage-data-보호", missing, verifyCommands);

  const defaultEncryption = readJson(options.commandRunner, "aws", awsArgs("ec2", "get-ebs-encryption-by-default", [], options));
  if (!defaultEncryption.ok) return commandUnknown("foundational/ebs-기반-workload-storage-data-보호", defaultEncryption.error, "read-only AWS 자격 증명으로 EBS 기본 암호화 상태를 조회하세요.", verifyCommands);

  const storageClasses = readJson(options.commandRunner, "kubectl", kubectlArgs(["get", "storageclass", "-o", "json"], options));
  if (!storageClasses.ok) return commandUnknown("foundational/ebs-기반-workload-storage-data-보호", storageClasses.error, "kubectl로 StorageClass 객체를 조회하세요.", verifyCommands);

  const pvcs = readJson(options.commandRunner, "kubectl", kubectlArgs(["get", "pvc", "-A", "-o", "json"], options));
  if (!pvcs.ok) return commandUnknown("foundational/ebs-기반-workload-storage-data-보호", pvcs.error, "kubectl로 PVC 객체를 조회하세요.", verifyCommands);

  const pvs = readJson(options.commandRunner, "kubectl", kubectlArgs(["get", "pv", "-o", "json"], options));
  if (!pvs.ok) return commandUnknown("foundational/ebs-기반-workload-storage-data-보호", pvs.error, "kubectl로 PV 객체를 조회하세요.", verifyCommands);

  const failures = [];
  if (defaultEncryption.data.EbsEncryptionByDefault !== true) failures.push("이 리전에서 AWS EBS 기본 암호화가 활성화되어 있지 않습니다.");

  const classByName = new Map((storageClasses.data.items ?? []).map((storageClass) => [storageClass.metadata?.name, storageClass]));
  for (const storageClass of storageClasses.data.items ?? []) {
    if (storageClass.provisioner === "ebs.csi.aws.com" || storageClass.provisioner === "kubernetes.io/aws-ebs") {
      if (String(storageClass.parameters?.encrypted).toLowerCase() !== "true") {
        failures.push(`StorageClass ${storageClass.metadata?.name ?? "<unnamed>"}가 parameters.encrypted=true를 설정하지 않았습니다.`);
      }
    }
  }

  for (const pvc of pvcs.data.items ?? []) {
    const storageClassName = pvc.spec?.storageClassName;
    if (!storageClassName || !classByName.has(storageClassName)) {
      failures.push(`${pvc.metadata?.namespace ?? "default"}/${pvc.metadata?.name ?? "<unnamed>"} PVC가 확인된 암호화 StorageClass를 참조하지 않습니다.`);
    }
  }

  const volumeIds = (pvs.data.items ?? [])
    .map((pv) => volumeIdFromHandle(pv.spec?.csi?.volumeHandle ?? pv.spec?.awsElasticBlockStore?.volumeID))
    .filter(Boolean);
  if (volumeIds.length > 0) {
    const volumes = readJson(options.commandRunner, "aws", awsArgs("ec2", "describe-volumes", ["--volume-ids", ...volumeIds], options));
    if (!volumes.ok) return commandUnknown("foundational/ebs-기반-workload-storage-data-보호", volumes.error, "read-only AWS 자격 증명으로 backing EBS volume을 조회하세요.", verifyCommands);
    for (const volume of volumes.data.Volumes ?? []) {
      if (volume.Encrypted !== true) failures.push(`EBS volume ${volume.VolumeId}가 암호화되어 있지 않습니다.`);
    }
  }

  return finding(
    "foundational/ebs-기반-workload-storage-data-보호",
    failures.length > 0 ? "fail" : "pass",
    failures.length > 0 ? "high" : "low",
    failures.length > 0 ? failures : ["EBS 기본 암호화, StorageClass 암호화, PVC 참조, 관측된 EBS PV volume 암호화가 모두 확인되었습니다."],
    "EBS 기본 암호화를 활성화하고, 암호화된 EBS CSI StorageClass를 요구하며, 암호화되지 않은 PV 기반 워크로드는 마이그레이션하세요.",
    verifyCommands,
  );
}

function checkLiveHardcodedSecretRemoval(options) {
  const verifyCommands = [
    "kubectl get externalsecrets -A -o json",
    "kubectl get deployments,statefulsets,daemonsets,jobs,cronjobs -A -o json",
  ];
  if (!options.context) return missingLiveConfig("foundational/workload-내-hardcoded-secret-제거", ["context"], verifyCommands);

  const externalSecrets = readJson(options.commandRunner, "kubectl", kubectlArgs(["get", "externalsecrets", "-A", "-o", "json"], options));
  if (!externalSecrets.ok) return commandUnknown("foundational/workload-내-hardcoded-secret-제거", externalSecrets.error, "kubectl로 ExternalSecret 객체를 조회하세요. CRD가 없다면 선택한 외부 Secret 경로를 설치하거나 문서화하세요.", verifyCommands);

  const workloads = readJson(options.commandRunner, "kubectl", kubectlArgs(["get", "deployments,statefulsets,daemonsets,jobs,cronjobs", "-A", "-o", "json"], options));
  if (!workloads.ok) return commandUnknown("foundational/workload-내-hardcoded-secret-제거", workloads.error, "kubectl로 워크로드 env 구성을 조회하세요.", verifyCommands);

  const failures = (workloads.data.items ?? [])
    .filter((item) => hasHardcodedSecret(workloadPodSpecForLive(item)))
    .map((item) => `${item.metadata?.namespace ?? "default"}/${item.kind ?? "Workload"}/${item.metadata?.name ?? "<unnamed>"}에 env 형식의 Secret literal이 포함되어 있습니다.`);
  const externalSecretCount = (externalSecrets.data.items ?? []).length;
  const status = failures.length > 0 ? "fail" : externalSecretCount > 0 ? "pass" : "warn";

  return finding(
    "foundational/workload-내-hardcoded-secret-제거",
    status,
    failures.length > 0 ? "high" : status === "warn" ? "medium" : "low",
    failures.length > 0 ? failures : [`${externalSecretCount}개 ExternalSecret 객체를 찾았고 Secret처럼 보이는 literal env 값은 관측되지 않았습니다.`],
    "런타임 Secret은 AWS Secrets Manager 또는 승인된 외부 Secret 경로로 옮기고 valueFrom, ESO, CSI 또는 런타임 조회 방식으로 참조하세요.",
    verifyCommands,
  );
}

function isDefaultRbacObject(item) {
  const name = item.metadata?.name ?? "";
  const labels = item.metadata?.labels ?? {};
  return name.startsWith("system:") || labels["kubernetes.io/bootstrapping"] === "rbac-defaults";
}

function hasWildcardRule(item) {
  return (item.rules ?? []).some((rule) => (rule.verbs ?? []).includes("*") || (rule.resources ?? []).includes("*"));
}

function checkLiveRbac(options) {
  const verifyCommands = [
    "kubectl get roles,rolebindings -A -o json",
    "kubectl get clusterroles,clusterrolebindings -o json",
  ];
  if (!options.context) return missingLiveConfig("foundational/cluster내-리소스-접근제어", ["context"], verifyCommands);

  const namespaced = readJson(options.commandRunner, "kubectl", kubectlArgs(["get", "roles,rolebindings", "-A", "-o", "json"], options));
  if (!namespaced.ok) return commandUnknown("foundational/cluster내-리소스-접근제어", namespaced.error, "kubectl로 namespace 범위 RBAC 객체를 조회하세요.", verifyCommands);

  const cluster = readJson(options.commandRunner, "kubectl", kubectlArgs(["get", "clusterroles,clusterrolebindings", "-o", "json"], options));
  if (!cluster.ok) return commandUnknown("foundational/cluster내-리소스-접근제어", cluster.error, "kubectl로 cluster 범위 RBAC 객체를 조회하세요.", verifyCommands);

  const items = [...(namespaced.data.items ?? []), ...(cluster.data.items ?? [])];
  const failures = [];
  for (const item of items) {
    if ((item.kind === "Role" || item.kind === "ClusterRole") && !isDefaultRbacObject(item) && hasWildcardRule(item)) {
      failures.push(`${item.kind}/${item.metadata?.name ?? "<unnamed>"}가 wildcard RBAC 권한을 사용합니다.`);
    }
    if (item.kind === "ClusterRoleBinding" && item.roleRef?.name === "cluster-admin" && !isDefaultRbacObject(item)) {
      failures.push(`ClusterRoleBinding/${item.metadata?.name ?? "<unnamed>"}가 cluster-admin을 바인딩합니다.`);
    }
  }

  const roleBindings = items.filter((item) => item.kind === "RoleBinding").length;
  const status = failures.length > 0 ? "fail" : roleBindings > 0 ? "pass" : "warn";
  return finding(
    "foundational/cluster내-리소스-접근제어",
    status,
    failures.length > 0 ? "high" : status === "warn" ? "medium" : "low",
    failures.length > 0 ? failures : [`${roleBindings}개 RoleBinding 객체를 찾았고, 사용자 정의 wildcard RBAC 또는 cluster-admin 바인딩은 관측되지 않았습니다.`],
    "네임스페이스 RBAC를 명시적으로 유지하고 wildcard 권한을 피하며, ClusterRoleBinding 사용은 검토된 platform role로 제한하세요.",
    verifyCommands,
  );
}

export function scanRepository({ repoRoot = process.cwd() } = {}) {
  const absoluteRoot = path.resolve(repoRoot);
  const entries = loadDocuments(absoluteRoot);
  const findings = [
    checkNonRoot(entries),
    checkServiceAccounts(entries),
    checkIngressTls(entries),
    checkQuotaAndLimits(entries),
    checkHardcodedSecrets(entries),
  ];

  return {
    scanner: "eks-maturity-advisor",
    mode: "repo-only",
    repo_root: absoluteRoot,
    findings: sortFindings(findings),
  };
}

export function scanLiveCluster({ clusterName, context, region, profile, autoDetect = false, commandRunner = defaultCommandRunner } = {}) {
  const detected = autoDetect ? detectLiveConfig({ commandRunner }) : {};
  const options = {
    clusterName: clusterName ?? detected.clusterName,
    context: context ?? detected.context,
    region: region ?? detected.region,
    profile: profile ?? detected.profile,
    commandRunner,
  };
  const findings = [
    checkLivePrivateApiEndpoint(options),
    checkLivePrivateSubnets(options),
    checkLiveDefaultDenyNetworkPolicy(options),
    checkLivePodSecurityBaseline(options),
    checkLiveIamK8sMapping(options),
    checkLiveContainerImageTriage(options),
    checkLiveGrafana(options),
    checkLiveEbsStorageProtection(options),
    checkLiveHardcodedSecretRemoval(options),
    checkLiveRbac(options),
  ];

  return {
    scanner: "eks-maturity-advisor",
    mode: "live-cluster",
    cluster_name: options.clusterName ?? null,
    kubectl_context: options.context ?? null,
    region: options.region ?? null,
    aws_profile: options.profile ?? null,
    findings: sortFindings(findings),
  };
}

export function renderMarkdown(report) {
  const lines = ["# EKS Maturity Advisor Report", "", `Mode: ${report.mode}`, ""];
  for (const finding of report.findings) {
    lines.push(`## ${finding.item_id}`, "", `Phase: ${finding.phase}`, `Domain: ${finding.domain}`, `Status: ${finding.status}`, `Severity: ${finding.severity}`, `Priority: ${finding.priority}`, "", "증거:");
    for (const item of finding.evidence) lines.push(`- ${item}`);
    lines.push("", `권장 조치: ${finding.recommendation}`, "");
  }
  return `${lines.join("\n")}\n`;
}

function parseArgs(argv) {
  const args = { repoRoot: process.cwd(), output: "json", live: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--repo-root") args.repoRoot = argv[++index];
    if (arg === "--output") args.output = argv[++index];
    if (arg === "--live") args.live = true;
    if (arg === "--context") args.context = argv[++index];
    if (arg === "--cluster-name") args.clusterName = argv[++index];
    if (arg === "--region") args.region = argv[++index];
    if (arg === "--profile") args.profile = argv[++index];
    if (arg === "--auto-detect") args.autoDetect = true;
  }
  return args;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = parseArgs(process.argv.slice(2));
  const report = args.live ? scanLiveCluster(args) : scanRepository({ repoRoot: args.repoRoot });
  process.stdout.write(args.output === "markdown" ? renderMarkdown(report) : `${JSON.stringify(report, null, 2)}\n`);
}
