import SwiftUI
import Combine

@MainActor
final class CacheCleanerModel: ObservableObject {
    @Published var entries: [ERCacheEntry] = []
    @Published var selected: Set<String> = []
    @Published var busy = false
    @Published var ready = false
    @Published var status = "Scan to find cached files. Nothing is selected automatically."
    @Published var messages: [String] = []
    private let cleaner = ERCacheCleaner()
    private var discardScan = false

    func scan(temporary: Bool, maxInode: Int) {
        guard !busy else { return }
        invalidate()
        busy = true
        discardScan = false
        status = "Finding apps and measuring caches…"
        cleaner.scan(withGroup: wq.getAppGroup(), includeTemporary: temporary,
                     maxInode: UInt64(max(1, maxInode))) { [weak self] result in
            MainActor.assumeIsolated {
                guard let self else { return }
                busy = false
                messages = result.messages
                guard !discardScan, !result.interrupted else {
                    entries = []
                    status = "Scan stopped. Scan again before cleaning."
                    return
                }
                entries = result.entries
                ready = true
                status = "\(entries.count) apps · \(Self.bytes(entries.reduce(0) { $0 + $1.cacheBytes + $1.temporaryBytes }))"
            }
        }
    }

    func clean() {
        guard ready, !busy, !selected.isEmpty else { return }
        let items = entries.filter { selected.contains($0.containerPath) }
        ready = false
        selected.removeAll()
        busy = true
        status = "Cleaning…"
        cleaner.cleanEntries(items, group: wq.getAppGroup()) { [weak self] result in
            MainActor.assumeIsolated {
                guard let self else { return }
                busy = false
                entries = []
                messages = result.messages
                status = "Removed \(Self.bytes(result.removedBytes)) in \(result.removedFiles) files."
                if result.skippedFiles > 0 { status += " Skipped \(result.skippedFiles) changed or inaccessible files." }
                if result.interrupted { status += " Stopped early." }
                status += " Scan again to refresh sizes."
            }
        }
    }

    func invalidate() {
        cleaner.cancel()
        discardScan = true
        ready = false
        selected.removeAll()
        if !busy { entries = [] }
    }

    static func bytes(_ value: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: value), countStyle: .file)
    }
}

struct CacheCleanerView: View {
    @StateObject private var model = CacheCleanerModel()
    @Environment(\.scenePhase) private var phase
    @AppStorage("maxInode") private var maxInode = 7_500_000
    @State private var includeTemporary = false
    @State private var filter = ""
    @State private var sortByName = false
    @State private var confirming = false

    private var visibleEntries: [ERCacheEntry] {
        model.entries.filter { filter.isEmpty || $0.identifier.localizedCaseInsensitiveContains(filter) }
            .sorted {
                sortByName ? $0.identifier.localizedStandardCompare($1.identifier) == .orderedAscending :
                    $0.cacheBytes + $0.temporaryBytes > $1.cacheBytes + $1.temporaryBytes
            }
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text(model.status)
                    if model.busy {
                        HStack {
                            ProgressView()
                            Button("Stop") { model.invalidate() }
                        }
                    } else {
                        Button("Scan") { model.scan(temporary: includeTemporary, maxInode: maxInode) }
                    }
                    Toggle("Include temporary files", isOn: $includeTemporary)
                        .disabled(model.busy)
                        .onChange(of: includeTemporary) { model.invalidate() }
                } footer: {
                    Text("App caches only. Scans are bounded and may miss apps. Sizes are logical, not guaranteed freed storage.")
                }

                if !model.entries.isEmpty {
                    Section {
                        ForEach(visibleEntries, id: \.containerPath) { item in
                            Toggle(isOn: Binding(
                                get: { model.selected.contains(item.containerPath) },
                                set: { if $0 { model.selected.insert(item.containerPath) }
                                       else { model.selected.remove(item.containerPath) } }
                            )) {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(item.identifier).font(.subheadline).textSelection(.enabled)
                                    Text("\(CacheCleanerModel.bytes(item.cacheBytes)) cache · \(CacheCleanerModel.bytes(item.temporaryBytes)) temporary")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                            }
                            .disabled(model.busy || !model.ready)
                        }
                    } header: { Text("Apps") }
                }

                if !model.messages.isEmpty {
                    Section("Skipped") {
                        ForEach(Array(model.messages.enumerated()), id: \.offset) { _, message in
                            Text(message).font(.footnote)
                        }
                    }
                }

                Section {
                    Button("Clean selected (\(model.selected.count))", role: .destructive) { confirming = true }
                        .disabled(model.busy || !model.ready || model.selected.isEmpty)
                } footer: {
                    Text("Close selected apps first. Running apps cannot be detected. Offline downloads and unsent drafts stored in caches may be lost.")
                }
            }
            .navigationTitle("Cache Cleaner")
            .searchable(text: $filter, prompt: "Filter apps")
            .toolbar {
                Menu {
                    Toggle("Sort by name", isOn: $sortByName)
                    Button("Select 50 MB+") {
                        model.selected = Set(visibleEntries.filter { $0.cacheBytes + $0.temporaryBytes >= 50 * 1024 * 1024 }.map(\.containerPath))
                    }.disabled(model.busy || !model.ready)
                    Button("Deselect all") { model.selected.removeAll() }
                } label: { Label("Options", systemImage: "ellipsis") }
            }
            .alert("Clean selected caches?", isPresented: $confirming) {
                Button("Cancel", role: .cancel) {}
                Button("Apps are closed — clean", role: .destructive) {
                    guard phase == .active else { return }
                    model.clean()
                }
            } message: {
                Text("This permanently removes the scanned cache files. Offline content may need downloading again. Erosion cannot check whether apps are running.")
            }
        }
        .onChange(of: phase) {
            if phase != .active { confirming = false; model.invalidate() }
        }
        .onDisappear { confirming = false; model.invalidate() }
    }
}
