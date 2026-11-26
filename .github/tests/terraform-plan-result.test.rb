require 'digest'
require 'fileutils'
require 'json'
require 'minitest/autorun'
require 'open3'
require 'tmpdir'
require 'yaml'

class TerraformPlanResultTest < Minitest::Test
  WORKFLOW = YAML.load_file(File.expand_path('../workflows/template-deploy-terraform.yml', __dir__))
  STEPS = WORKFLOW.fetch('jobs').fetch('terraform-plan').fetch('steps')
  PLAN = STEPS.find { |step| step['id'] == 'tf-plan' }
  RESULT = STEPS.find { |step| step['id'] == 'plan-result' }
  UPLOAD = STEPS.find { |step| step['name'] == 'Publish Terraform plan result' }

  def setup
    @dir = Dir.mktmpdir('terraform-plan-test-')
    @output = File.join(@dir, 'output')
    @event = File.join(@dir, 'event.json')
    File.write(@event, JSON.generate(pull_request: {
      number: 42, head: { sha: 'head-sha' }, base: { sha: 'base-sha' }
    }))
    File.write(File.join(@dir, 'terraform'), <<~SH)
      #!/bin/bash
      printf '%s\\n' "$*" > "$ARGS_FILE"
      exit "$PLAN_CODE"
    SH
    FileUtils.chmod(0o755, File.join(@dir, 'terraform'))
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  def run_plan(code, skip_refresh)
    File.write(@output, '')
    env = {
      'PATH' => "#{@dir}:#{ENV.fetch('PATH')}", 'GITHUB_OUTPUT' => @output,
      'ARGS_FILE' => File.join(@dir, 'args'), 'PLAN_CODE' => code.to_s,
      'SKIP_STATE_REFRESH' => skip_refresh.to_s
    }
    _, stderr, status = Open3.capture3(env, 'bash', '-eo', 'pipefail', '-c', PLAN.fetch('run'))
    [status, File.read(@output), File.read(env.fetch('ARGS_FILE')), stderr]
  end

  def run_result(root: './terraform/app/', code: '0', refreshed: 'true')
    File.write(@output, '')
    env = {
      'ROOT' => root, 'EXIT_CODE' => code, 'REFRESHED' => refreshed,
      'GITHUB_OUTPUT' => @output, 'GITHUB_EVENT_PATH' => @event,
      'RUNNER_TEMP' => @dir, 'GITHUB_REPOSITORY' => 'org/repo',
      'GITHUB_SHA' => 'merge-sha', 'GITHUB_RUN_ID' => '123',
      'GITHUB_RUN_ATTEMPT' => '2'
    }
    _, stderr, status = Open3.capture3(env, 'bash', '-eo', 'pipefail', '-c', RESULT.fetch('run'))
    outputs = File.readlines(@output, chomp: true).to_h { |line| line.split('=', 2) }
    [status, outputs, stderr]
  end

  def test_plan_exit_codes_and_refresh_modes
    [false, true].each do |skip|
      [0, 1, 2, 127].each do |code|
        status, output, args, = run_plan(code, skip)
        assert_equal([0, 2].include?(code) ? 0 : code, status.exitstatus)
        assert_equal("exitcode=#{code}", output.lines.last.strip)
        assert_equal(skip, args.include?('-refresh=false'))
      end
    end
  end

  def test_pr_only_upload_and_apply_contract
    setup = STEPS.find { |step| step['name'] == 'Setup Terraform' }
    assert_equal(false, setup.fetch('with').fetch('terraform_wrapper'))
    assert_equal("github.event_name == 'pull_request'", RESULT.fetch('if'))
    assert_equal(RESULT.fetch('if'), UPLOAD.fetch('if'))
    assert_equal(7, UPLOAD.fetch('with').fetch('retention-days'))
    assert_equal('error', UPLOAD.fetch('with').fetch('if-no-files-found'))
    assert_equal('${{ steps.tf-plan.outputs.exitcode }}',
                 WORKFLOW.fetch('jobs').fetch('terraform-plan').fetch('outputs').fetch('tfplanExitCode'))
    assert_includes(WORKFLOW.fetch('jobs').fetch('terraform-apply').fetch('if'),
                    'needs.terraform-plan.outputs.tfplanExitCode == 2')
  end

  def test_evidence_contains_only_expected_metadata
    status, outputs, stderr = run_result
    assert(status.success?, stderr)
    root = 'terraform/app'
    assert_equal("terraform-plan-result-#{Digest::SHA256.hexdigest(root)}", outputs.fetch('name'))
    assert_equal('result.json', File.basename(outputs.fetch('path')))
    assert_equal(['result.json'], Dir.children(File.dirname(outputs.fetch('path'))))
    assert_equal({
      'schema_version' => 1, 'repository' => 'org/repo', 'pr_number' => 42,
      'head_sha' => 'head-sha', 'base_sha' => 'base-sha', 'merge_sha' => 'merge-sha',
      'run_id' => '123', 'run_attempt' => '2', 'root' => root,
      'refreshed' => true, 'exit_code' => 0
    }, JSON.parse(File.read(outputs.fetch('path'))))

    status, outputs, stderr = run_result(root: 'terraform/other/../app', code: '2', refreshed: 'false')
    assert(status.success?, stderr)
    assert_equal("terraform-plan-result-#{Digest::SHA256.hexdigest(root)}", outputs.fetch('name'))
    result = JSON.parse(File.read(outputs.fetch('path')))
    assert_equal(false, result.fetch('refreshed'))
    assert_equal(2, result.fetch('exit_code'))

    status, outputs, stderr = run_result(root: '.')
    assert(status.success?, stderr)
    assert_equal("terraform-plan-result-#{Digest::SHA256.hexdigest('.')}", outputs.fetch('name'))

    status, outputs, stderr = run_result(root: 'terraform/another')
    assert(status.success?, stderr)
    refute_equal("terraform-plan-result-#{Digest::SHA256.hexdigest(root)}", outputs.fetch('name'))
  end

  def test_invalid_inputs_do_not_produce_evidence
    ['', '/', '/terraform', '../outside', 'terraform/../../outside'].each do |root|
      status, outputs, = run_result(root: root)
      refute(status.success?, root)
      assert_empty(outputs)
    end
    ['', '1', '3'].each do |code|
      status, outputs, = run_result(code: code)
      refute(status.success?, code)
      assert_empty(outputs)
    end
    File.write(@event, '{}')
    status, outputs, = run_result
    refute(status.success?)
    assert_empty(outputs)
  end
end
