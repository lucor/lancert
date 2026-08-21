package registration

import (
	"fmt"
	"io"
)

const hostnameSuffixAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

var (
	adjectives = []string{
		"agile", "ancient", "brave", "bright", "calm", "clever", "cloudy", "cozy",
		"crisp", "curious", "dapper", "eager", "early", "fancy", "fast", "fuzzy",
		"gentle", "glad", "grand", "happy", "hidden", "jolly", "kind", "lively",
		"lucky", "merry", "misty", "modern", "noble", "patient", "peaceful", "playful",
		"polite", "proud", "quick", "quiet", "rapid", "ready", "restful", "round",
		"shiny", "silent", "simple", "sleek", "smart", "smooth", "soft", "steady",
		"still", "sturdy", "sunny", "swift", "tidy", "tiny", "tranquil", "trusty",
		"vivid", "warm", "wise", "witty", "young", "zesty", "nimble", "serene",
	}
	animals = []string{
		"alpaca", "badger", "beaver", "bison", "bobcat", "canary", "caribou", "cougar",
		"crane", "deer", "dolphin", "dove", "eagle", "falcon", "ferret", "finch",
		"fox", "gecko", "gopher", "heron", "ibis", "jaguar", "koala", "lemur",
		"leopard", "lion", "lynx", "marten", "moose", "narwhal", "ocelot", "otter",
		"owl", "panda", "parrot", "pelican", "penguin", "puffin", "rabbit", "raven",
		"robin", "salmon", "seal", "sparrow", "stoat", "swan", "tahr", "tapir",
		"tiger", "toucan", "turtle", "vicuna", "walrus", "weasel", "whale", "wombat",
		"yak", "zebra", "kestrel", "kingfisher", "meerkat", "orca", "quail", "wren",
	}
	objects = []string{
		"anchor", "anvil", "arrow", "basket", "beacon", "bell", "book", "bottle",
		"bridge", "button", "candle", "canvas", "carpet", "chisel", "clock", "compass",
		"drum", "feather", "flute", "frame", "gadget", "globe", "hammer", "harp",
		"helmet", "jacket", "kettle", "key", "lantern", "lattice", "loom", "maple",
		"mirror", "needle", "notebook", "paddle", "paper", "pencil", "pillow", "ribbon",
		"saddle", "sail", "shield", "spindle", "spoon", "stapler", "stone", "table",
		"telescope", "thread", "torch", "trumpet", "umbrella", "vase", "wheel", "whistle",
		"window", "wrench", "barrel", "bucket", "camera", "goblet", "magnet", "sundial",
	}
	places = []string{
		"bay", "beach", "bluff", "brook", "canyon", "cavern", "cliff", "coast",
		"cove", "creek", "dell", "desert", "dune", "field", "fjord", "forest",
		"garden", "glen", "grove", "harbor", "haven", "hill", "island", "lagoon",
		"lake", "marsh", "meadow", "mesa", "moor", "mountain", "oasis", "orchard",
		"park", "pass", "peak", "pond", "prairie", "reef", "ridge", "river",
		"shore", "spring", "summit", "trail", "valley", "village", "waterfall", "woodland",
		"basin", "cape", "delta", "estuary", "glade", "inlet", "isle", "plain",
		"plateau", "ravine", "savanna", "sound", "strait", "tundra", "vale", "wetland",
	}
	colors = []string{
		"aqua", "beige", "black", "blue", "bronze", "brown", "coral", "cream",
		"cyan", "gold", "gray", "green", "indigo", "ivory", "jade", "lilac",
		"lime", "magenta", "maroon", "navy", "ochre", "olive", "orange", "peach",
		"pink", "purple", "red", "silver", "teal", "turquoise", "white", "yellow",
	}
)

type hostnameTemplate struct {
	left  []string
	right []string
}

var hostnameTemplates = []hostnameTemplate{
	{adjectives, animals},
	{adjectives, objects},
	{adjectives, places},
	{colors, animals},
	{colors, objects},
	{animals, places},
}

func generateHostname(random io.Reader, withSuffix bool) (string, error) {
	templateIndex, err := randomIndex(random, len(hostnameTemplates))
	if err != nil {
		return "", fmt.Errorf("select template: %w", err)
	}
	template := hostnameTemplates[templateIndex]
	leftIndex, err := randomIndex(random, len(template.left))
	if err != nil {
		return "", fmt.Errorf("select first word: %w", err)
	}
	rightIndex, err := randomIndex(random, len(template.right))
	if err != nil {
		return "", fmt.Errorf("select second word: %w", err)
	}
	hostname := template.left[leftIndex] + "-" + template.right[rightIndex]
	if !withSuffix {
		return hostname, nil
	}
	first, err := randomIndex(random, len(hostnameSuffixAlphabet))
	if err != nil {
		return "", fmt.Errorf("select suffix: %w", err)
	}
	second, err := randomIndex(random, len(hostnameSuffixAlphabet))
	if err != nil {
		return "", fmt.Errorf("select suffix: %w", err)
	}
	return hostname + "-" + string([]byte{hostnameSuffixAlphabet[first], hostnameSuffixAlphabet[second]}), nil
}

func randomIndex(random io.Reader, size int) (int, error) {
	if size < 1 || size > 256 {
		return 0, fmt.Errorf("invalid bucket size %d", size)
	}
	limit := 256 - 256%size
	for {
		var value [1]byte
		if _, err := io.ReadFull(random, value[:]); err != nil {
			return 0, err
		}
		if int(value[0]) < limit {
			return int(value[0]) % size, nil
		}
	}
}

func validHostname(hostname string) bool {
	if len(hostname) < 1 || len(hostname) > 63 || hostname[0] == '-' || hostname[len(hostname)-1] == '-' {
		return false
	}
	for i := range len(hostname) {
		c := hostname[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}
