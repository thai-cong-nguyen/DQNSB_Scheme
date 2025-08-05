package internal

import (
	"crypto/md5"
	"crypto/sha256"
	"hash"
	"testing"
)

type TestSHA256Item struct {
	x string
}

func (t TestSHA256Item) CalculateHash() ([]byte, error) {
	hash := sha256.New()
	if _, err := hash.Write([]byte(t.x)); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func (t TestSHA256Item) Equals(other Item) (bool, error) {
	return t.x == other.(TestSHA256Item).x, nil
}

type TestMD5Item struct {
	x string
}

func (t TestMD5Item) CalculateHash() ([]byte, error) {
	hash := md5.New()
	if _, err := hash.Write([]byte(t.x)); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func (t TestMD5Item) Equals(other Item) (bool, error) {
	return t.x == other.(TestMD5Item).x, nil
}

var table = []struct {
	testCaseId          int
	hashStrategy        func() hash.Hash
	hashStrategyName    string
	defaultHashStrategy bool
	sort                bool
	items               []Item
	expectedHash        []byte
	notInItems          Item
}{
	{
		testCaseId:          0,
		hashStrategy:        sha256.New,
		hashStrategyName:    "sha256",
		defaultHashStrategy: true,
		sort:                false,
		items: []Item{
			TestSHA256Item{
				x: "Hello",
			},
			TestSHA256Item{
				x: "Hi",
			},
			TestSHA256Item{
				x: "Hey",
			},
			TestSHA256Item{
				x: "Hola",
			},
		},
		notInItems:   TestSHA256Item{x: "NotInTestTable"},
		expectedHash: []byte{95, 48, 204, 128, 19, 59, 147, 148, 21, 110, 36, 178, 51, 240, 196, 190, 50, 178, 78, 68, 187, 51, 129, 240, 44, 123, 165, 38, 25, 208, 254, 188},
	},
	{
		testCaseId:          1,
		hashStrategy:        sha256.New,
		hashStrategyName:    "sha256",
		defaultHashStrategy: true,
		sort:                false,
		items: []Item{
			TestSHA256Item{
				x: "Hello",
			},
			TestSHA256Item{
				x: "Hi",
			},
			TestSHA256Item{
				x: "Hey",
			},
		},
		notInItems:   TestSHA256Item{x: "NotInTestTable"},
		expectedHash: []byte{189, 214, 55, 197, 35, 237, 92, 14, 171, 121, 43, 152, 109, 177, 136, 80, 194, 57, 162, 226, 56, 2, 179, 106, 255, 38, 187, 104, 251, 63, 224, 8},
	},
	{
		testCaseId:          2,
		hashStrategy:        sha256.New,
		hashStrategyName:    "sha256",
		defaultHashStrategy: true,
		sort:                false,
		items: []Item{
			TestSHA256Item{
				x: "Hello",
			},
			TestSHA256Item{
				x: "Hi",
			},
			TestSHA256Item{
				x: "Hey",
			},
			TestSHA256Item{
				x: "Greetings",
			},
			TestSHA256Item{
				x: "Hola",
			},
		},
		notInItems:   TestSHA256Item{x: "NotInTestTable"},
		expectedHash: []byte{46, 216, 115, 174, 13, 210, 55, 39, 119, 197, 122, 104, 93, 144, 112, 131, 202, 151, 41, 14, 80, 143, 21, 71, 140, 169, 139, 173, 50, 37, 235, 188},
	},
	{
		testCaseId:          3,
		hashStrategy:        sha256.New,
		hashStrategyName:    "sha256",
		defaultHashStrategy: true,
		sort:                false,
		items: []Item{
			TestSHA256Item{
				x: "123",
			},
			TestSHA256Item{
				x: "234",
			},
			TestSHA256Item{
				x: "345",
			},
			TestSHA256Item{
				x: "456",
			},
			TestSHA256Item{
				x: "1123",
			},
			TestSHA256Item{
				x: "2234",
			},
			TestSHA256Item{
				x: "3345",
			},
			TestSHA256Item{
				x: "4456",
			},
		},
		notInItems:   TestSHA256Item{x: "NotInTestTable"},
		expectedHash: []byte{30, 76, 61, 40, 106, 173, 169, 183, 149, 2, 157, 246, 162, 218, 4, 70, 153, 148, 62, 162, 90, 24, 173, 250, 41, 149, 173, 121, 141, 187, 146, 43},
	},
	{
		testCaseId:          4,
		hashStrategy:        sha256.New,
		hashStrategyName:    "sha256",
		defaultHashStrategy: true,
		sort:                false,
		items: []Item{
			TestSHA256Item{
				x: "123",
			},
			TestSHA256Item{
				x: "234",
			},
			TestSHA256Item{
				x: "345",
			},
			TestSHA256Item{
				x: "456",
			},
			TestSHA256Item{
				x: "1123",
			},
			TestSHA256Item{
				x: "2234",
			},
			TestSHA256Item{
				x: "3345",
			},
			TestSHA256Item{
				x: "4456",
			},
			TestSHA256Item{
				x: "5567",
			},
		},
		notInItems:   TestSHA256Item{x: "NotInTestTable"},
		expectedHash: []byte{143, 37, 161, 192, 69, 241, 248, 56, 169, 87, 79, 145, 37, 155, 51, 159, 209, 129, 164, 140, 130, 167, 16, 182, 133, 205, 126, 55, 237, 188, 89, 236},
	},
	{
		testCaseId:          5,
		hashStrategy:        md5.New,
		hashStrategyName:    "md5",
		defaultHashStrategy: false,
		sort:                false,
		items: []Item{
			TestMD5Item{
				x: "Hello",
			},
			TestMD5Item{
				x: "Hi",
			},
			TestMD5Item{
				x: "Hey",
			},
			TestMD5Item{
				x: "Hola",
			},
		},
		notInItems:   TestMD5Item{x: "NotInTestTable"},
		expectedHash: []byte{217, 158, 206, 52, 191, 78, 253, 233, 25, 55, 69, 142, 254, 45, 127, 144},
	},
	{
		testCaseId:          6,
		hashStrategy:        md5.New,
		hashStrategyName:    "md5",
		defaultHashStrategy: false,
		sort:                false,
		items: []Item{
			TestMD5Item{
				x: "Hello",
			},
			TestMD5Item{
				x: "Hi",
			},
			TestMD5Item{
				x: "Hey",
			},
		},
		notInItems:   TestMD5Item{x: "NotInTestTable"},
		expectedHash: []byte{145, 228, 171, 107, 94, 219, 221, 171, 7, 195, 206, 128, 148, 98, 59, 76},
	},
	{
		testCaseId:          7,
		hashStrategy:        md5.New,
		hashStrategyName:    "md5",
		defaultHashStrategy: false,
		sort:                false,
		items: []Item{
			TestMD5Item{
				x: "Hello",
			},
			TestMD5Item{
				x: "Hi",
			},
			TestMD5Item{
				x: "Hey",
			},
			TestMD5Item{
				x: "Greetings",
			},
			TestMD5Item{
				x: "Hola",
			},
		},
		notInItems:   TestMD5Item{x: "NotInTestTable"},
		expectedHash: []byte{167, 200, 229, 62, 194, 247, 117, 12, 206, 194, 90, 235, 70, 14, 100, 100},
	},
	{
		testCaseId:          8,
		hashStrategy:        md5.New,
		hashStrategyName:    "md5",
		defaultHashStrategy: false,
		sort:                false,
		items: []Item{
			TestMD5Item{
				x: "123",
			},
			TestMD5Item{
				x: "234",
			},
			TestMD5Item{
				x: "345",
			},
			TestMD5Item{
				x: "456",
			},
			TestMD5Item{
				x: "1123",
			},
			TestMD5Item{
				x: "2234",
			},
			TestMD5Item{
				x: "3345",
			},
			TestMD5Item{
				x: "4456",
			},
		},
		notInItems:   TestMD5Item{x: "NotInTestTable"},
		expectedHash: []byte{8, 36, 33, 50, 204, 197, 82, 81, 207, 74, 6, 60, 162, 209, 168, 21},
	},
	{
		testCaseId:          9,
		hashStrategy:        md5.New,
		hashStrategyName:    "md5",
		defaultHashStrategy: false,
		sort:                false,
		items: []Item{
			TestMD5Item{
				x: "123",
			},
			TestMD5Item{
				x: "234",
			},
			TestMD5Item{
				x: "345",
			},
			TestMD5Item{
				x: "456",
			},
			TestMD5Item{
				x: "1123",
			},
			TestMD5Item{
				x: "2234",
			},
			TestMD5Item{
				x: "3345",
			},
			TestMD5Item{
				x: "4456",
			},
			TestMD5Item{
				x: "5567",
			},
		},
		notInItems:   TestMD5Item{x: "NotInTestTable"},
		expectedHash: []byte{158, 85, 181, 191, 25, 250, 251, 71, 215, 22, 68, 68, 11, 198, 244, 148},
	},
	{
		testCaseId:          10,
		hashStrategy:        md5.New,
		hashStrategyName:    "md5",
		defaultHashStrategy: false,
		sort:                true,
		items: []Item{
			TestMD5Item{
				x: "123",
			},
			TestMD5Item{
				x: "234",
			},
			TestMD5Item{
				x: "345",
			},
			TestMD5Item{
				x: "456",
			},
			TestMD5Item{
				x: "1123",
			},
			TestMD5Item{
				x: "2234",
			},
			TestMD5Item{
				x: "3345",
			},
			TestMD5Item{
				x: "4456",
			},
			TestMD5Item{
				x: "5567",
			},
		},
		notInItems:   TestMD5Item{x: "NotInTestTable"},
		expectedHash: []byte{22, 110, 37, 8, 31, 141, 31, 96, 181, 30, 77, 25, 39, 224, 220, 180},
	},
}

func TestMerkleTree_String(t *testing.T) {
	for i := 0; i < len(table); i++ {
		var tree *MerkleTree
		var err error
		if table[i].defaultHashStrategy {
			tree, err = NewMerkleTree(table[i].items)
		}
		if err != nil {
			t.Errorf("Test case %d failed: %v", table[i].testCaseId, err)
		}
		if tree.String() == "" {
			t.Errorf("Test case %d failed: String representation is empty", table[i].testCaseId)
		}
	}
}
