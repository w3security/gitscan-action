#!/usr/bin/env bats
bats_load_library bats-support
bats_load_library bats-assert
bats_load_library bats-file

@test "gitscan repo with securityCheck secret only" {
  # gitscan repo --format json --output repo.test --security-checks=secret https://github.com/cyberoslab/demo-gitscan/
  run ./entrypoint.sh '-b json' '-h repo.test' '-s secret' '-a repo' '-j https://github.com/cyberoslab/demo-gitscan/'
  run diff repo.test ./test/data/repo.test
  echo "$output"
  assert_files_equal repo.test ./test/data/repo.test
}

@test "gitscan image" {
  # gitscan image --severity CRITICAL --output image.test knqyf263/vuln-image:1.2.3
  run ./entrypoint.sh '-a image' '-i knqyf263/vuln-image:1.2.3' '-h image.test' '-g CRITICAL'
  run diff image.test ./test/data/image.test
  echo "$output"
  assert_files_equal image.test ./test/data/image.test
}

@test "gitscan config sarif report" {
  # gitscan config --format sarif --output  config-sarif.test .
  run ./entrypoint.sh '-a config' '-b sarif' '-h config-sarif.test' '-j .'
  run diff config-sarif.test ./test/data/config-sarif.test
  echo "$output"
  assert_files_equal config-sarif.test ./test/data/config-sarif.test
}

@test "gitscan config" {
  # gitscan config --format json --output config.test .
  run ./entrypoint.sh '-a config' '-b json' '-j .' '-h config.test'
  run diff config.test ./test/data/config.test
  echo "$output"
  assert_files_equal config.test ./test/data/config.test
}

@test "gitscan rootfs" {
  # gitscan rootfs --output rootfs.test .
  run ./entrypoint.sh '-a rootfs' '-j .' '-h rootfs.test'
  run diff rootfs.test ./test/data/rootfs.test
  echo "$output"
  assert_files_equal rootfs.test ./test/data/rootfs.test
}

@test "gitscan fs" {
  # gitscan fs --output fs.test .
  run ./entrypoint.sh '-a fs' '-j .' '-h fs.test'
  run diff fs.test ./test/data/fs.test
  echo "$output"
  assert_files_equal fs.test ./test/data/fs.test
}

@test "gitscan fs with securityChecks option" {
  # gitscan fs --format json --security-checks=vuln,config --output fs-scheck.test .
  run ./entrypoint.sh '-a fs' '-b json' '-j .' '-s vuln,config,secret' '-h fs-scheck.test'
  run diff fs-scheck.test ./test/data/fs-scheck.test
  echo "$output"
  assert_files_equal fs-scheck.test ./test/data/fs-scheck.test
}


@test "gitscan image with gitscanIgnores option" {
  # cat ./test/data/.gitscanignore1 ./test/data/.gitscanignore2 > ./gitscanignores ; gitscan image --severity CRITICAL  --output image-gitscanignores.test --ignorefile ./gitscanignores knqyf263/vuln-image:1.2.3
  run ./entrypoint.sh '-a image' '-i knqyf263/vuln-image:1.2.3' '-h image-gitscanignores.test' '-g CRITICAL' '-t ./test/data/.gitscanignore1,./test/data/.gitscanignore2'
  run diff image-gitscanignores.test ./test/data/image-gitscanignores.test
  echo "$output"
  assert_files_equal image-gitscanignores.test ./test/data/image-gitscanignores.test
}

@test "gitscan image with sbom output" {
  # gitscan image --format  github knqyf263/vuln-image:1.2.3
  run ./entrypoint.sh  "-a image" "-b github" "-i knqyf263/vuln-image:1.2.3"
  assert_output --partial '"package_url": "pkg:apk/ca-certificates@20171114-r0",' # TODO: Output contains time, need to mock
}

@test "gitscan image with gitscan.yaml config" {
  # gitscan --config=./test/data/gitscan.yaml image alpine:3.10
  run ./entrypoint.sh "-v ./test/data/gitscan.yaml" "-a image" "-i alpine:3.10"
  run diff yamlconfig.test ./test/data/yamlconfig.test
  echo "$output"
  assert_files_equal yamlconfig.test ./test/data/yamlconfig.test
}
