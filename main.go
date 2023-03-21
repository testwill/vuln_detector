package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"

	"github.com/aquasecurity/trivy/pkg/detector/library"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	pkgTargets = map[string]string{
		ftypes.PythonPkg: "Python",
		ftypes.CondaPkg:  "Conda",
		ftypes.GemSpec:   "Ruby",
		ftypes.NodePkg:   "Node.js",
		ftypes.Jar:       "Java",
	}
)

func main() {
	var (
		imgName string
		options types.ScanOptions
	)
	options.ListAllPackages = true
	flag.StringVar(&imgName, "image", "", "镜像名")
	flag.Parse()
	var blobList []ftypes.BlobInfo
	file, _ := os.ReadFile("test.json")
	err := json.Unmarshal(file, &blobList)
	if err != nil {
		log.Logger.Fatal("Unmarshal error :", err)
	}

	db.Init(fsutils.DefaultCacheDir())
	detector := ospkg.Detector{}
	detail := applier.ApplyLayers(blobList)
	vulns, eosl, err := detector.Detect(imgName, blobList[0].OS.Family, blobList[0].OS.Name, &ftypes.Repository{}, time.Time{}, detail.Packages)
	if err != nil {
		log.Logger.Fatal(err)
	}
	log.Logger.Info("eosl :", eosl)
	artifactDetail := fmt.Sprintf("%s (%s %s)", imgName, detail.OS.Family, detail.OS.Name)

	result := &types.Result{
		Target:          artifactDetail,
		Vulnerabilities: vulns,
		Class:           types.ClassOSPkg,
		Type:            blobList[0].OS.Family,
	}

	data, _ := json.Marshal(result)
	fmt.Println(string(data))
	var results types.Results
	if detail.Applications != nil {
		printedTypes := map[string]struct{}{}
		for _, app := range detail.Applications {
			if len(app.Libraries) == 0 {
				continue
			}

			// Prevent the same log messages from being displayed many times for the same type.
			if _, ok := printedTypes[app.Type]; !ok {
				log.Logger.Infof("Detecting %s vulnerabilities...", app.Type)
				printedTypes[app.Type] = struct{}{}
			}

			log.Logger.Infof("Detecting library vulnerabilities, type: %s, path: %s", app.Type, app.FilePath)
			vulns, err := library.Detect(app.Type, app.Libraries)
			if err != nil {
				log.Logger.Fatal("failed vulnerability detection of libraries: %w", err)
			} else if len(vulns) == 0 {
				continue
			}

			target := app.FilePath
			if t, ok := pkgTargets[app.Type]; ok && target == "" {
				// When the file path is empty, we will overwrite it with the pre-defined value.
				target = t
			}

			results = append(results, types.Result{
				Target:          target,
				Vulnerabilities: vulns,
				Class:           types.ClassLangPkg,
				Type:            app.Type,
			})
		}
		sort.Slice(results, func(i, j int) bool {
			return results[i].Target < results[j].Target
		})
	}

	data, _ = json.Marshal(results)
	log.Logger.Info(string(data))
	results = append(results, *result)
	log.Logger.Info("os and libraries vulnerability :")
	data, _ = json.Marshal(results)
	log.Logger.Info(string(data))
}
