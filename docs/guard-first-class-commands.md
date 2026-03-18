# Guard First-Class Commands Proposal

## Goal

`guard` should recognize not only `aws`, but also AWS ecosystem tools that an AI agent realistically runs from a Bash tool. Since `aws-sso-login` is an AWS SSO tool, the scope is limited to commands that manage **AWS resources**.

1. Parse shell structure with `mvdan.cc/sh/v3`
2. Resolve the real command after wrappers (`env`, `sudo`, `command`, `time`, `nice`, shell `-c`)
3. Classify the command into a first-class tool family
4. Classify the operation as one of:
   - `read`
   - `mutate`
   - `destructive`
   - `exec`
   - `unknown`
5. Apply policy:
   - `read`: allow
   - `mutate` / `destructive` / `exec`: block or ask
   - `unknown`: fail closed unless `--fail-open`

## Recommended rollout

### P0: implement first

AWS-native and primary IaC tools:

- `aws` (existing — keep profile check + add command-risk classification)
- `terraform`
- `terragrunt`
- `cdk`
- `sam`
- `serverless` / `sls`

### P1: add next

AWS-adjacent (EKS/ECS management):

- `kubectl` (EKS)
- `helm` (EKS)
- `eksctl`
- `pulumi`
- `docker` (ECR/ECS)

## Classification matrix

### 1. AWS CLI

| Priority | Command | Dangerous subcommands / flags | Safe operations | Notes |
|---|---|---|---|---|
| P0 | `aws` | `s3 rm`, `s3 mv`, `s3 cp` to `s3://`, `s3 sync` to `s3://`, any `--delete`; verb families like `create*`, `put*`, `update*`, `delete*`, `modify*`, `attach*`, `detach*`, `associate*`, `disassociate*`, `register*`, `deregister*`, `run*`, `start*`, `stop*`, `reboot*`, `terminate*`, `tag*`, `untag*`, `execute*`; CloudFormation `deploy`, `delete-stack`, `update-stack`, `create-stack`; IAM `put-*`, `attach-*`, `create-*`, `delete-*`, `update-*` | `sts get-caller-identity`, `s3 ls`, `ec2 describe-*`, `rds describe-*`, `iam get-*`, `iam list-*`, `cloudformation describe-*`, `cloudformation list-*`, `eks describe-*`, `logs tail`, `logs describe-*` | Existing `--profile` readonly check stays as a separate policy axis |

### 2. IaC tools (AWS-focused)

| Priority | Command | Dangerous subcommands / flags | Safe operations | Notes |
|---|---|---|---|---|
| P0 | `terraform` | `apply`, `destroy`, `import`, `taint`, `untaint`, `state rm`, `state mv`, `state push`, `state replace-provider`, `workspace delete`; `plan -destroy`; `apply -replace=...` | `init`, `validate`, `fmt`, `version`, `providers`, `show`, `output`, `graph`, `state list`, `state show`, `state pull`, `workspace list`, `workspace show`, `plan` (without `-destroy`) | `plan` is read-only unless `-destroy`; `import` mutates state even if infra is unchanged |
| P0 | `terragrunt` | `apply`, `destroy`, `run-all apply`, `run-all destroy`, `import`, `state rm`, `state mv`, `state push`, `taint`, `untaint` | `hclfmt`, `validate`, `plan`, `show`, `output`, `graph-dependencies` | Mirror Terraform plus `run-all` variants |
| P0 | `cdk` | `deploy`, `destroy`, `rollback`, `watch` | `synth`, `diff`, `list`, `doctor`, `metadata`, `context` read operations | `watch` can redeploy automatically, so treat as mutate |
| P1 | `pulumi` | `up`, `destroy`, `import`, `refresh`, `cancel`, `stack rm`, `state delete`, `state unprotect` | `preview`, `about`, `whoami`, `stack output`, `stack ls`, `config get`, `logs` | `refresh` is state mutation, even if not infra mutation |

### 3. AWS serverless frameworks

| Priority | Command | Dangerous subcommands / flags | Safe operations | Notes |
|---|---|---|---|---|
| P0 | `sam` | `deploy`, `delete`, `sync`, `remote invoke`; `publish` | `validate`, `build`, `package`, `list`, `logs` | `remote invoke` is function execution, not read |
| P0 | `serverless` / `sls` | `deploy`, `remove`, `rollback`, `invoke`, `plugin install`, `plugin uninstall` | `print`, `package`, `info`, `logs` | `invoke` can create side effects |

### 4. EKS / ECS management

| Priority | Command | Dangerous subcommands / flags | Safe operations | Notes |
|---|---|---|---|---|
| P1 | `kubectl` | `apply`, `create`, `delete`, `replace`, `patch`, `edit`, `scale`, `autoscale`, `rollout restart`, `set image`, `set env`, `label`, `annotate`, `cordon`, `uncordon`, `drain`, `taint`; `exec`, `cp`, `port-forward` as `exec` | `get`, `describe`, `logs`, `top`, `diff`, `cluster-info`, `api-resources`, `api-versions`, `auth can-i`, `version`, `explain` | `exec`/`cp`/`port-forward` provide privileged runtime access |
| P1 | `helm` | `install`, `upgrade`, `uninstall`, `rollback`; `repo add` / `repo remove` | `list`, `status`, `history`, `show`, `search`, `template`, `lint`, `get values`, `get manifest`, `get hooks`, `get all` | `helm diff upgrade` is read if first command is `diff` |
| P1 | `eksctl` | `create`, `delete`, `upgrade`, `scale`, `drain`, `set`, `enable`, `disable`, `utils update-*`; `create iamidentitymapping` | `get cluster`, `get nodegroup`, `utils describe-stacks`, `version` | EKS-specific, realistic in AWS environments |
| P1 | `docker` | `push` (to ECR), `run`, `exec`, `rm`, `rmi`, `stop`, `kill`, `restart`, `compose up`, `compose down`, `compose exec`, `compose run` | `ps`, `images`, `inspect`, `logs`, `stats`, `pull`, `compose ps`, `compose logs`, `compose config` | Primarily relevant for ECR pushes and ECS local testing |

## Practical matching rules

### Rule 1: classify by verb, not only by command name

- `terraform plan` -> `read`
- `terraform plan -destroy` -> `destructive`
- `terraform apply` -> `mutate`
- `aws ec2 describe-instances` -> `read`
- `aws cloudformation deploy` -> `mutate`
- `aws s3 sync ./dist s3://bucket --delete` -> `destructive`
- `kubectl get pods` -> `read`
- `kubectl exec deploy/api -- sh` -> `exec`
- `sam deploy` -> `mutate`
- `serverless invoke` -> `exec`

### Rule 2: treat remote execution as dangerous

These should not be classified as read-only:

- `kubectl exec`
- `docker exec` / `docker run`
- `serverless invoke`
- `sam remote invoke`

Reason: they execute code against live AWS systems.

### Rule 3: treat dynamic values as `unknown`

- `terraform $ACTION`
- `kubectl $VERB pods`
- `aws s3 $OP s3://bucket`

If a first-class tool is recognized but the mutability cannot be determined statically, fail closed.

### Rule 4: inspect nested command structures

Must still work through:

- `bash -lc 'terraform apply'`
- `env AWS_PROFILE=prod kubectl apply -f k8s.yaml`
- `sudo sam deploy`

This already aligns with the current `AnalyzeCommand` recursion model.

## Recommended guard behavior

### Keep the current AWS profile guard

Current behavior stays as a separate policy axis:

- if `aws` uses `--profile prod`, block when not `-ro`
- if `AWS_PROFILE=prod aws ...`, block

### Add command risk classification

- `read`: allow
- `mutate`: ask by default, optionally block
- `destructive`: block by default
- `exec`: ask or block depending on strictness
- `unknown`: block unless `--fail-open`

## Suggested CLI changes

Current:

```bash
aws-sso-login guard --readonly-only
```

Suggested:

```bash
aws-sso-login guard \
  --readonly-only \
  --classify-commands \
  --block-risk destructive \
  --ask-risk mutate,exec
```

Or presets:

```bash
aws-sso-login guard --policy conservative  # allow read, ask mutate+exec, block destructive+unknown
aws-sso-login guard --policy strict        # allow read, block everything else
```

## Suggested implementation shape

Data-driven rule table instead of hardcoded `switch`:

```go
type Risk int

const (
    RiskRead Risk = iota
    RiskMutate
    RiskDestructive
    RiskExec
    RiskUnknown
)

type CommandRule struct {
    Names    []string
    Classify func(args []string) (Risk, string)
}

var rules = []CommandRule{
    awsRule(),
    terraformRule(),
    terragruntRule(),
    cdkRule(),
    samRule(),
    serverlessRule(),
    // P1
    kubectlRule(),
    helmRule(),
    eksctlRule(),
    pulumiRule(),
    dockerRule(),
}
```

## Bottom line

P0 (6 commands): `aws`, `terraform`, `terragrunt`, `cdk`, `sam`, `serverless`
P1 (5 commands): `kubectl`, `helm`, `eksctl`, `pulumi`, `docker`

Total 11 commands, all within the AWS ecosystem.
