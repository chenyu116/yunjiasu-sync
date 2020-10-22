package main

import (
	"fmt"
	"github.com/chenyu116/yunjiasu-sync/yunjiasu"
)

var (
	_version_   = ""
	_branch_    = ""
	_commitId_  = ""
	_buildTime_ = ""
)

func main() {
	fmt.Printf("Version: %s, Branch: %s, Build: %s, Build time: %s\n",
		_version_, _branch_, _commitId_, _buildTime_)
	yunjiasu.Run()
}
